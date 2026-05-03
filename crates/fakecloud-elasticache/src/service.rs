use std::convert::TryFrom;
use std::sync::Arc;

use async_trait::async_trait;
use http::StatusCode;
use tokio::sync::Mutex as AsyncMutex;

use fakecloud_aws::xml::xml_escape;
use fakecloud_core::query::{optional_query_param, query_response_xml, required_query_param};
use fakecloud_core::service::{AwsRequest, AwsResponse, AwsService, AwsServiceError};
use fakecloud_persistence::SnapshotStore;

use crate::runtime::{ElastiCacheRuntime, RuntimeError};
use crate::state::{
    default_engine_versions, default_parameters_for_family, CacheCluster, CacheEngineVersion,
    CacheParameterGroup, CacheSnapshot, CacheSubnetGroup, ElastiCacheSnapshot, ElastiCacheState,
    ElastiCacheUser, ElastiCacheUserGroup, EngineDefaultParameter, GlobalReplicationGroup,
    GlobalReplicationGroupMember, LogDeliveryConfiguration, RecurringCharge, ReplicationGroup,
    ReservedCacheNode, ReservedCacheNodesOffering, ServerlessCache, ServerlessCacheDataStorage,
    ServerlessCacheEcpuPerSecond, ServerlessCacheEndpoint, ServerlessCacheSnapshot,
    ServerlessCacheUsageLimits, SharedElastiCacheState, ELASTICACHE_SNAPSHOT_SCHEMA_VERSION,
};

const ELASTICACHE_NS: &str = "http://elasticache.amazonaws.com/doc/2015-02-02/";

/// Cache engine wire values. Stored as ``String`` on ``CacheCluster`` etc., but
/// validated against this list at the wire boundary so a typo can't slip in.
const ENGINE_REDIS: &str = "redis";
const ENGINE_VALKEY: &str = "valkey";
const ENGINE_MEMCACHED: &str = "memcached";
const SUPPORTED_ENGINES: &[&str] = &[ENGINE_REDIS, ENGINE_VALKEY, ENGINE_MEMCACHED];

fn validate_engine(engine: &str) -> Result<(), AwsServiceError> {
    if !SUPPORTED_ENGINES.contains(&engine) {
        return Err(AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "InvalidParameterValue",
            format!(
                "Invalid value for Engine: {engine}. Supported engines: redis, valkey, memcached"
            ),
        ));
    }
    Ok(())
}

fn reject_memcached_for(engine: &str, feature: &str) -> Result<(), AwsServiceError> {
    if engine == ENGINE_MEMCACHED {
        return Err(AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "InvalidParameterValue",
            format!("{feature} is not supported for the memcached engine."),
        ));
    }
    Ok(())
}
const SUPPORTED_ACTIONS: &[&str] = &[
    "AddTagsToResource",
    "CreateCacheCluster",
    "CreateGlobalReplicationGroup",
    "CreateCacheSubnetGroup",
    "CreateReplicationGroup",
    "CreateServerlessCache",
    "CreateServerlessCacheSnapshot",
    "CreateSnapshot",
    "CreateUser",
    "CreateUserGroup",
    "DecreaseReplicaCount",
    "DeleteCacheCluster",
    "DeleteGlobalReplicationGroup",
    "DeleteCacheSubnetGroup",
    "DeleteReplicationGroup",
    "DeleteServerlessCache",
    "DeleteServerlessCacheSnapshot",
    "DeleteSnapshot",
    "DeleteUser",
    "DeleteUserGroup",
    "DescribeCacheClusters",
    "DescribeCacheEngineVersions",
    "DescribeGlobalReplicationGroups",
    "DescribeCacheParameterGroups",
    "DescribeReservedCacheNodes",
    "DescribeReservedCacheNodesOfferings",
    "DescribeCacheSubnetGroups",
    "DescribeEngineDefaultParameters",
    "DescribeReplicationGroups",
    "DescribeServerlessCaches",
    "DescribeServerlessCacheSnapshots",
    "DescribeSnapshots",
    "DescribeUserGroups",
    "DescribeUsers",
    "DisassociateGlobalReplicationGroup",
    "FailoverGlobalReplicationGroup",
    "IncreaseReplicaCount",
    "ListTagsForResource",
    "ModifyCacheSubnetGroup",
    "ModifyGlobalReplicationGroup",
    "ModifyReplicationGroup",
    "ModifyServerlessCache",
    "RemoveTagsFromResource",
    "TestFailover",
    "AuthorizeCacheSecurityGroupIngress",
    "RevokeCacheSecurityGroupIngress",
    "CreateCacheSecurityGroup",
    "DeleteCacheSecurityGroup",
    "DescribeCacheSecurityGroups",
    "CreateCacheParameterGroup",
    "DeleteCacheParameterGroup",
    "ModifyCacheParameterGroup",
    "ResetCacheParameterGroup",
    "DescribeCacheParameters",
    "ModifyCacheCluster",
    "RebootCacheCluster",
    "ListAllowedNodeTypeModifications",
    "ModifyReplicationGroupShardConfiguration",
    "DecreaseNodeGroupsInGlobalReplicationGroup",
    "IncreaseNodeGroupsInGlobalReplicationGroup",
    "RebalanceSlotsInGlobalReplicationGroup",
    "ModifyUser",
    "ModifyUserGroup",
    "PurchaseReservedCacheNodesOffering",
    "DescribeEvents",
    "DescribeServiceUpdates",
    "DescribeUpdateActions",
    "BatchApplyUpdateAction",
    "BatchStopUpdateAction",
    "CopySnapshot",
    "CopyServerlessCacheSnapshot",
    "ExportServerlessCacheSnapshot",
    "StartMigration",
    "CompleteMigration",
    "TestMigration",
];

pub struct ElastiCacheService {
    state: SharedElastiCacheState,
    runtime: Option<Arc<ElastiCacheRuntime>>,
    snapshot_store: Option<Arc<dyn SnapshotStore>>,
    snapshot_lock: Arc<AsyncMutex<()>>,
}

impl ElastiCacheService {
    pub fn new(state: SharedElastiCacheState) -> Self {
        Self {
            state,
            runtime: None,
            snapshot_store: None,
            snapshot_lock: Arc::new(AsyncMutex::new(())),
        }
    }

    pub fn with_runtime(mut self, runtime: Arc<ElastiCacheRuntime>) -> Self {
        self.runtime = Some(runtime);
        self
    }

    pub fn with_snapshot_store(mut self, store: Arc<dyn SnapshotStore>) -> Self {
        self.snapshot_store = Some(store);
        self
    }

    async fn save_snapshot(&self) {
        let Some(store) = self.snapshot_store.clone() else {
            return;
        };
        let _guard = self.snapshot_lock.lock().await;
        let snapshot = ElastiCacheSnapshot {
            schema_version: ELASTICACHE_SNAPSHOT_SCHEMA_VERSION,
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
            Ok(Err(err)) => tracing::error!(%err, "failed to write elasticache snapshot"),
            Err(err) => tracing::error!(%err, "elasticache snapshot task panicked"),
        }
    }
}

fn is_mutating_action(action: &str) -> bool {
    !matches!(
        action,
        "DescribeCacheClusters"
            | "DescribeCacheEngineVersions"
            | "DescribeGlobalReplicationGroups"
            | "DescribeCacheParameterGroups"
            | "DescribeReservedCacheNodes"
            | "DescribeReservedCacheNodesOfferings"
            | "DescribeCacheSubnetGroups"
            | "DescribeEngineDefaultParameters"
            | "DescribeReplicationGroups"
            | "DescribeServerlessCaches"
            | "DescribeServerlessCacheSnapshots"
            | "DescribeSnapshots"
            | "DescribeUserGroups"
            | "DescribeUsers"
            | "ListTagsForResource"
            | "DescribeCacheSecurityGroups"
            | "DescribeCacheParameters"
            | "DescribeEvents"
            | "DescribeServiceUpdates"
            | "DescribeUpdateActions"
            | "ListAllowedNodeTypeModifications"
            | "TestMigration"
    )
}

#[async_trait]
impl AwsService for ElastiCacheService {
    fn service_name(&self) -> &str {
        "elasticache"
    }

    async fn handle(&self, request: AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let mutates = is_mutating_action(request.action.as_str());
        let result = match request.action.as_str() {
            "AddTagsToResource" => self.add_tags_to_resource(&request),
            "CreateCacheCluster" => self.create_cache_cluster(&request).await,
            "CreateGlobalReplicationGroup" => self.create_global_replication_group(&request),
            "CreateCacheSubnetGroup" => self.create_cache_subnet_group(&request),
            "CreateReplicationGroup" => self.create_replication_group(&request).await,
            "CreateServerlessCache" => self.create_serverless_cache(&request).await,
            "CreateServerlessCacheSnapshot" => self.create_serverless_cache_snapshot(&request),
            "CreateSnapshot" => self.create_snapshot(&request),
            "CreateUser" => self.create_user(&request),
            "CreateUserGroup" => self.create_user_group(&request),
            "DecreaseReplicaCount" => self.decrease_replica_count(&request),
            "DeleteCacheCluster" => self.delete_cache_cluster(&request).await,
            "DeleteGlobalReplicationGroup" => self.delete_global_replication_group(&request),
            "DeleteCacheSubnetGroup" => self.delete_cache_subnet_group(&request),
            "DeleteReplicationGroup" => self.delete_replication_group(&request).await,
            "DeleteServerlessCache" => self.delete_serverless_cache(&request).await,
            "DeleteServerlessCacheSnapshot" => self.delete_serverless_cache_snapshot(&request),
            "DeleteSnapshot" => self.delete_snapshot(&request),
            "DeleteUser" => self.delete_user(&request),
            "DeleteUserGroup" => self.delete_user_group(&request),
            "DescribeCacheClusters" => self.describe_cache_clusters(&request),
            "DescribeCacheEngineVersions" => self.describe_cache_engine_versions(&request),
            "DescribeGlobalReplicationGroups" => self.describe_global_replication_groups(&request),
            "DescribeCacheParameterGroups" => self.describe_cache_parameter_groups(&request),
            "DescribeReservedCacheNodes" => self.describe_reserved_cache_nodes(&request),
            "DescribeReservedCacheNodesOfferings" => {
                self.describe_reserved_cache_nodes_offerings(&request)
            }
            "DescribeCacheSubnetGroups" => self.describe_cache_subnet_groups(&request),
            "DescribeEngineDefaultParameters" => self.describe_engine_default_parameters(&request),
            "DescribeReplicationGroups" => self.describe_replication_groups(&request),
            "DescribeServerlessCaches" => self.describe_serverless_caches(&request),
            "DescribeServerlessCacheSnapshots" => {
                self.describe_serverless_cache_snapshots(&request)
            }
            "DescribeSnapshots" => self.describe_snapshots(&request),
            "DescribeUserGroups" => self.describe_user_groups(&request),
            "DescribeUsers" => self.describe_users(&request),
            "DisassociateGlobalReplicationGroup" => {
                self.disassociate_global_replication_group(&request)
            }
            "FailoverGlobalReplicationGroup" => self.failover_global_replication_group(&request),
            "IncreaseReplicaCount" => self.increase_replica_count(&request),
            "ListTagsForResource" => self.list_tags_for_resource(&request),
            "ModifyCacheSubnetGroup" => self.modify_cache_subnet_group(&request),
            "ModifyGlobalReplicationGroup" => self.modify_global_replication_group(&request),
            "ModifyReplicationGroup" => self.modify_replication_group(&request),
            "ModifyServerlessCache" => self.modify_serverless_cache(&request),
            "RemoveTagsFromResource" => self.remove_tags_from_resource(&request),
            "TestFailover" => self.test_failover(&request),
            "AuthorizeCacheSecurityGroupIngress" => {
                self.authorize_cache_security_group_ingress(&request)
            }
            "RevokeCacheSecurityGroupIngress" => self.revoke_cache_security_group_ingress(&request),
            "CreateCacheSecurityGroup" => self.create_cache_security_group(&request),
            "DeleteCacheSecurityGroup" => self.delete_cache_security_group(&request),
            "DescribeCacheSecurityGroups" => self.describe_cache_security_groups(&request),
            "CreateCacheParameterGroup" => self.create_cache_parameter_group(&request),
            "DeleteCacheParameterGroup" => self.delete_cache_parameter_group(&request),
            "ModifyCacheParameterGroup" => self.modify_cache_parameter_group(&request),
            "ResetCacheParameterGroup" => self.reset_cache_parameter_group(&request),
            "DescribeCacheParameters" => self.describe_cache_parameters(&request),
            "ModifyCacheCluster" => self.modify_cache_cluster(&request),
            "RebootCacheCluster" => self.reboot_cache_cluster(&request).await,
            "ListAllowedNodeTypeModifications" => {
                self.list_allowed_node_type_modifications(&request)
            }
            "ModifyReplicationGroupShardConfiguration" => {
                self.modify_replication_group_shard_configuration(&request)
            }
            "DecreaseNodeGroupsInGlobalReplicationGroup" => {
                self.decrease_node_groups_in_global_replication_group(&request)
            }
            "IncreaseNodeGroupsInGlobalReplicationGroup" => {
                self.increase_node_groups_in_global_replication_group(&request)
            }
            "RebalanceSlotsInGlobalReplicationGroup" => {
                self.rebalance_slots_in_global_replication_group(&request)
            }
            "ModifyUser" => self.modify_user(&request),
            "ModifyUserGroup" => self.modify_user_group(&request),
            "PurchaseReservedCacheNodesOffering" => {
                self.purchase_reserved_cache_nodes_offering(&request)
            }
            "DescribeEvents" => self.describe_events(&request),
            "DescribeServiceUpdates" => self.describe_service_updates(&request),
            "DescribeUpdateActions" => self.describe_update_actions(&request),
            "BatchApplyUpdateAction" => self.batch_apply_update_action(&request),
            "BatchStopUpdateAction" => self.batch_stop_update_action(&request),
            "CopySnapshot" => self.copy_snapshot(&request),
            "CopyServerlessCacheSnapshot" => self.copy_serverless_cache_snapshot(&request),
            "ExportServerlessCacheSnapshot" => self.export_serverless_cache_snapshot(&request),
            "StartMigration" => self.start_migration(&request),
            "CompleteMigration" => self.complete_migration(&request),
            "TestMigration" => self.test_migration(&request),
            _ => Err(AwsServiceError::action_not_implemented(
                self.service_name(),
                &request.action,
            )),
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

impl ElastiCacheService {
    fn describe_cache_engine_versions(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let engine = optional_query_param(request, "Engine");
        let engine_version = optional_query_param(request, "EngineVersion");
        let family = optional_query_param(request, "CacheParameterGroupFamily");
        let default_only =
            parse_optional_bool(optional_query_param(request, "DefaultOnly").as_deref())?;
        let max_records = optional_usize_param(request, "MaxRecords")?;
        let marker = optional_query_param(request, "Marker");

        let mut versions = filter_engine_versions(
            &default_engine_versions(),
            &engine,
            &engine_version,
            &family,
        );

        if default_only.unwrap_or(false) {
            // Keep only one version per engine (the latest)
            let mut seen_engines = std::collections::HashSet::new();
            versions.retain(|v| seen_engines.insert(v.engine.clone()));
        }

        let (page, next_marker) = paginate(&versions, marker.as_deref(), max_records);

        let members_xml: String = page.iter().map(engine_version_xml).collect();
        let marker_xml = next_marker
            .map(|m| format!("<Marker>{}</Marker>", xml_escape(&m)))
            .unwrap_or_default();

        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "DescribeCacheEngineVersions",
                ELASTICACHE_NS,
                &format!("<CacheEngineVersions>{members_xml}</CacheEngineVersions>{marker_xml}"),
                &request.request_id,
            ),
        ))
    }

    fn describe_cache_parameter_groups(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let group_name = optional_query_param(request, "CacheParameterGroupName");
        let max_records = optional_usize_param(request, "MaxRecords")?;
        let marker = optional_query_param(request, "Marker");

        let accounts = self.state.read();
        let empty = ElastiCacheState::new(&request.account_id, &request.region);
        let state = accounts.get(&request.account_id).unwrap_or(&empty);

        let groups: Vec<&CacheParameterGroup> = state
            .parameter_groups
            .iter()
            .filter(|g| {
                group_name
                    .as_ref()
                    .is_none_or(|name| g.cache_parameter_group_name == *name)
            })
            .collect();

        if let Some(ref name) = group_name {
            if groups.is_empty() {
                return Err(AwsServiceError::aws_error(
                    StatusCode::NOT_FOUND,
                    "CacheParameterGroupNotFound",
                    format!("CacheParameterGroup {name} not found."),
                ));
            }
        }

        let (page, next_marker) = paginate(&groups, marker.as_deref(), max_records);

        let members_xml: String = page.iter().map(|g| cache_parameter_group_xml(g)).collect();
        let marker_xml = next_marker
            .map(|m| format!("<Marker>{}</Marker>", xml_escape(&m)))
            .unwrap_or_default();

        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "DescribeCacheParameterGroups",
                ELASTICACHE_NS,
                &format!("<CacheParameterGroups>{members_xml}</CacheParameterGroups>{marker_xml}"),
                &request.request_id,
            ),
        ))
    }

    fn describe_reserved_cache_nodes(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let reserved_cache_node_id = optional_query_param(request, "ReservedCacheNodeId");
        let reserved_cache_nodes_offering_id =
            optional_query_param(request, "ReservedCacheNodesOfferingId");
        let cache_node_type = optional_query_param(request, "CacheNodeType");
        let duration = parse_reserved_duration_filter(optional_query_param(request, "Duration"))?;
        let product_description = optional_query_param(request, "ProductDescription");
        let offering_type = optional_query_param(request, "OfferingType");
        let max_records = optional_usize_param(request, "MaxRecords")?;
        let marker = optional_query_param(request, "Marker");

        let accounts = self.state.read();
        let empty = ElastiCacheState::new(&request.account_id, &request.region);
        let state = accounts.get(&request.account_id).unwrap_or(&empty);
        let mut nodes: Vec<&ReservedCacheNode> = state.reserved_cache_nodes.values().collect();
        nodes.retain(|node| {
            reserved_cache_node_id
                .as_ref()
                .is_none_or(|expected| node.reserved_cache_node_id == *expected)
                && reserved_cache_nodes_offering_id
                    .as_ref()
                    .is_none_or(|expected| node.reserved_cache_nodes_offering_id == *expected)
                && cache_node_type
                    .as_ref()
                    .is_none_or(|expected| node.cache_node_type == *expected)
                && duration.is_none_or(|expected| node.duration == expected)
                && product_description
                    .as_ref()
                    .is_none_or(|expected| node.product_description == *expected)
                && offering_type
                    .as_ref()
                    .is_none_or(|expected| node.offering_type == *expected)
        });
        nodes.sort_by(|left, right| {
            left.reserved_cache_node_id
                .cmp(&right.reserved_cache_node_id)
        });

        if let Some(ref id) = reserved_cache_node_id {
            if nodes.is_empty() {
                return Err(AwsServiceError::aws_error(
                    StatusCode::NOT_FOUND,
                    "ReservedCacheNodeNotFoundFault",
                    format!("ReservedCacheNode not found: {id}"),
                ));
            }
        }

        let (page, next_marker) = paginate(&nodes, marker.as_deref(), max_records);
        let members_xml: String = page
            .iter()
            .map(|node| reserved_cache_node_xml(node))
            .collect();
        let marker_xml = next_marker
            .map(|value| format!("<Marker>{}</Marker>", xml_escape(&value)))
            .unwrap_or_default();

        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "DescribeReservedCacheNodes",
                ELASTICACHE_NS,
                &format!("<ReservedCacheNodes>{members_xml}</ReservedCacheNodes>{marker_xml}"),
                &request.request_id,
            ),
        ))
    }

    fn describe_reserved_cache_nodes_offerings(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let reserved_cache_nodes_offering_id =
            optional_query_param(request, "ReservedCacheNodesOfferingId");
        let cache_node_type = optional_query_param(request, "CacheNodeType");
        let duration = parse_reserved_duration_filter(optional_query_param(request, "Duration"))?;
        let product_description = optional_query_param(request, "ProductDescription");
        let offering_type = optional_query_param(request, "OfferingType");
        let max_records = optional_usize_param(request, "MaxRecords")?;
        let marker = optional_query_param(request, "Marker");

        let accounts = self.state.read();
        let empty = ElastiCacheState::new(&request.account_id, &request.region);
        let state = accounts.get(&request.account_id).unwrap_or(&empty);
        let mut offerings: Vec<&ReservedCacheNodesOffering> =
            state.reserved_cache_nodes_offerings.iter().collect();
        offerings.retain(|offering| {
            reserved_cache_nodes_offering_id
                .as_ref()
                .is_none_or(|expected| offering.reserved_cache_nodes_offering_id == *expected)
                && cache_node_type
                    .as_ref()
                    .is_none_or(|expected| offering.cache_node_type == *expected)
                && duration.is_none_or(|expected| offering.duration == expected)
                && product_description
                    .as_ref()
                    .is_none_or(|expected| offering.product_description == *expected)
                && offering_type
                    .as_ref()
                    .is_none_or(|expected| offering.offering_type == *expected)
        });
        offerings.sort_by(|left, right| {
            left.reserved_cache_nodes_offering_id
                .cmp(&right.reserved_cache_nodes_offering_id)
        });

        if let Some(ref id) = reserved_cache_nodes_offering_id {
            if offerings.is_empty() {
                return Err(AwsServiceError::aws_error(
                    StatusCode::NOT_FOUND,
                    "ReservedCacheNodesOfferingNotFoundFault",
                    format!("ReservedCacheNodesOffering not found: {id}"),
                ));
            }
        }

        let (page, next_marker) = paginate(&offerings, marker.as_deref(), max_records);
        let members_xml: String = page
            .iter()
            .map(|offering| reserved_cache_nodes_offering_xml(offering))
            .collect();
        let marker_xml = next_marker
            .map(|value| format!("<Marker>{}</Marker>", xml_escape(&value)))
            .unwrap_or_default();

        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "DescribeReservedCacheNodesOfferings", ELASTICACHE_NS,
                &format!(
                    "<ReservedCacheNodesOfferings>{members_xml}</ReservedCacheNodesOfferings>{marker_xml}"
                ),
                &request.request_id,
            ),
        ))
    }

    fn describe_engine_default_parameters(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let family = required_query_param(request, "CacheParameterGroupFamily")?;
        let max_records = optional_usize_param(request, "MaxRecords")?;
        let marker = optional_query_param(request, "Marker");

        let params = default_parameters_for_family(&family);
        let (page, next_marker) = paginate(&params, marker.as_deref(), max_records);

        let params_xml: String = page.iter().map(parameter_xml).collect();
        let marker_xml = next_marker
            .map(|m| format!("<Marker>{}</Marker>", xml_escape(&m)))
            .unwrap_or_default();

        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "DescribeEngineDefaultParameters",
                ELASTICACHE_NS,
                &format!(
                    "<EngineDefaults>\
                     <CacheParameterGroupFamily>{}</CacheParameterGroupFamily>\
                     <Parameters>{params_xml}</Parameters>\
                     {marker_xml}\
                     </EngineDefaults>",
                    xml_escape(&family),
                ),
                &request.request_id,
            ),
        ))
    }

    fn create_cache_subnet_group(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let name = required_query_param(request, "CacheSubnetGroupName")?;
        let description = required_query_param(request, "CacheSubnetGroupDescription")?;
        let subnet_ids = parse_member_list(&request.query_params, "SubnetIds", "SubnetIdentifier");

        if subnet_ids.is_empty() {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidParameterValue",
                "At least one subnet ID must be specified.".to_string(),
            ));
        }

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request.account_id);

        if state.subnet_groups.contains_key(&name) {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "CacheSubnetGroupAlreadyExists",
                format!("Cache subnet group {name} already exists."),
            ));
        }

        let arn = format!(
            "arn:aws:elasticache:{}:{}:subnetgroup:{}",
            state.region, state.account_id, name
        );
        let vpc_id = format!(
            "vpc-{:08x}",
            name.as_bytes()
                .iter()
                .fold(0u32, |acc, &b| acc.wrapping_add(b as u32))
        );

        let group = CacheSubnetGroup {
            cache_subnet_group_name: name.clone(),
            cache_subnet_group_description: description,
            vpc_id,
            subnet_ids,
            arn,
        };

        let xml = cache_subnet_group_xml(&group, &state.region);
        state.register_arn(&group.arn);
        state.subnet_groups.insert(name, group);

        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "CreateCacheSubnetGroup",
                ELASTICACHE_NS,
                &format!("<CacheSubnetGroup>{xml}</CacheSubnetGroup>"),
                &request.request_id,
            ),
        ))
    }

    fn describe_cache_subnet_groups(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let group_name = optional_query_param(request, "CacheSubnetGroupName");
        let max_records = optional_usize_param(request, "MaxRecords")?;
        let marker = optional_query_param(request, "Marker");

        let accounts = self.state.read();
        let empty = ElastiCacheState::new(&request.account_id, &request.region);
        let state = accounts.get(&request.account_id).unwrap_or(&empty);

        let groups: Vec<&CacheSubnetGroup> = if let Some(ref name) = group_name {
            match state.subnet_groups.get(name) {
                Some(g) => vec![g],
                None => {
                    return Err(AwsServiceError::aws_error(
                        StatusCode::NOT_FOUND,
                        "CacheSubnetGroupNotFoundFault",
                        format!("Cache subnet group {name} not found."),
                    ));
                }
            }
        } else {
            let mut groups: Vec<&CacheSubnetGroup> = state.subnet_groups.values().collect();
            groups.sort_by(|a, b| a.cache_subnet_group_name.cmp(&b.cache_subnet_group_name));
            groups
        };

        let (page, next_marker) = paginate(&groups, marker.as_deref(), max_records);

        let members_xml: String = page
            .iter()
            .map(|g| {
                format!(
                    "<CacheSubnetGroup>{}</CacheSubnetGroup>",
                    cache_subnet_group_xml(g, &state.region)
                )
            })
            .collect();
        let marker_xml = next_marker
            .map(|m| format!("<Marker>{}</Marker>", xml_escape(&m)))
            .unwrap_or_default();

        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "DescribeCacheSubnetGroups",
                ELASTICACHE_NS,
                &format!("<CacheSubnetGroups>{members_xml}</CacheSubnetGroups>{marker_xml}"),
                &request.request_id,
            ),
        ))
    }

    fn delete_cache_subnet_group(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let name = required_query_param(request, "CacheSubnetGroupName")?;

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request.account_id);

        if name == "default" {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "CacheSubnetGroupInUse",
                "Cannot delete default cache subnet group.".to_string(),
            ));
        }

        if let Some(group) = state.subnet_groups.remove(&name) {
            state.tags.remove(&group.arn);
        } else {
            return Err(AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "CacheSubnetGroupNotFoundFault",
                format!("Cache subnet group {name} not found."),
            ));
        }

        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "DeleteCacheSubnetGroup",
                ELASTICACHE_NS,
                "",
                &request.request_id,
            ),
        ))
    }

    fn modify_cache_subnet_group(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let name = required_query_param(request, "CacheSubnetGroupName")?;
        let description = optional_query_param(request, "CacheSubnetGroupDescription");
        let subnet_ids = parse_member_list(&request.query_params, "SubnetIds", "SubnetIdentifier");

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request.account_id);
        let region = state.region.clone();

        let group = state.subnet_groups.get_mut(&name).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "CacheSubnetGroupNotFoundFault",
                format!("Cache subnet group {name} not found."),
            )
        })?;

        if let Some(desc) = description {
            group.cache_subnet_group_description = desc;
        }
        if !subnet_ids.is_empty() {
            group.subnet_ids = subnet_ids;
        }

        let xml = cache_subnet_group_xml(group, &region);

        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "ModifyCacheSubnetGroup",
                ELASTICACHE_NS,
                &format!("<CacheSubnetGroup>{xml}</CacheSubnetGroup>"),
                &request.request_id,
            ),
        ))
    }

    async fn create_cache_cluster(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let cache_cluster_id = required_query_param(request, "CacheClusterId")?;
        let engine =
            optional_query_param(request, "Engine").unwrap_or_else(|| ENGINE_REDIS.to_string());
        validate_engine(&engine)?;

        let default_version = match engine.as_str() {
            ENGINE_VALKEY => "8.0",
            ENGINE_MEMCACHED => "1.6.22",
            _ => "7.1",
        };
        let engine_version = optional_query_param(request, "EngineVersion")
            .unwrap_or_else(|| default_version.to_string());
        let cache_node_type = optional_query_param(request, "CacheNodeType")
            .unwrap_or_else(|| "cache.t3.micro".to_string());
        let num_cache_nodes = match optional_query_param(request, "NumCacheNodes") {
            Some(v) => {
                let n = v.parse::<i32>().map_err(|_| {
                    AwsServiceError::aws_error(
                        StatusCode::BAD_REQUEST,
                        "InvalidParameterValue",
                        format!("Invalid value for NumCacheNodes: '{v}'"),
                    )
                })?;
                if n < 1 {
                    return Err(AwsServiceError::aws_error(
                        StatusCode::BAD_REQUEST,
                        "InvalidParameterValue",
                        format!("NumCacheNodes must be a positive integer, got {n}"),
                    ));
                }
                n
            }
            None => 1,
        };
        let cache_subnet_group_name = optional_query_param(request, "CacheSubnetGroupName")
            .or_else(|| Some("default".to_string()));
        let replication_group_id = optional_query_param(request, "ReplicationGroupId");
        let auto_minor_version_upgrade = parse_optional_bool(
            optional_query_param(request, "AutoMinorVersionUpgrade").as_deref(),
        )?
        .unwrap_or(true);
        let cache_parameter_group_name = optional_query_param(request, "CacheParameterGroupName");
        let security_group_ids =
            parse_query_list_param(request, "SecurityGroupIds", "SecurityGroupId");
        let cache_security_group_names =
            parse_query_list_param(request, "CacheSecurityGroupNames", "CacheSecurityGroupName");
        let log_delivery_configurations = parse_log_delivery_configs(request);
        let transit_encryption_enabled = parse_optional_bool(
            optional_query_param(request, "TransitEncryptionEnabled").as_deref(),
        )?
        .unwrap_or(false);
        let at_rest_encryption_enabled = parse_optional_bool(
            optional_query_param(request, "AtRestEncryptionEnabled").as_deref(),
        )?
        .unwrap_or(false);
        let auth_token = optional_query_param(request, "AuthToken");
        let auth_token_enabled = auth_token.is_some();
        // ElastiCache defaults: 6379 redis/valkey, 11211 memcached.
        let default_port = if engine == ENGINE_MEMCACHED {
            11211
        } else {
            6379
        };
        let port = optional_query_param(request, "Port")
            .and_then(|v| v.parse::<u16>().ok())
            .unwrap_or(default_port);
        let preferred_maintenance_window =
            optional_query_param(request, "PreferredMaintenanceWindow");
        let preferred_availability_zones =
            parse_query_list_param(request, "PreferredAvailabilityZones", "AvailabilityZone");
        let notification_topic_arn = optional_query_param(request, "NotificationTopicArn");
        let snapshot_arns = parse_query_list_param(request, "SnapshotArns", "SnapshotArn");
        let snapshot_name = optional_query_param(request, "SnapshotName");
        let snapshot_retention_limit = optional_query_param(request, "SnapshotRetentionLimit")
            .and_then(|v| v.parse::<i32>().ok())
            .unwrap_or(0);
        let snapshot_window = optional_query_param(request, "SnapshotWindow");
        let outpost_mode = optional_query_param(request, "OutpostMode");
        let preferred_outpost_arn = optional_query_param(request, "PreferredOutpostArn");
        // Default to ipv4 when unspecified, matching AWS's default network stack.
        let network_type =
            Some(optional_query_param(request, "NetworkType").unwrap_or_else(|| "ipv4".into()));
        let ip_discovery =
            Some(optional_query_param(request, "IpDiscovery").unwrap_or_else(|| "ipv4".into()));
        let az_mode =
            Some(optional_query_param(request, "AZMode").unwrap_or_else(|| "single-az".into()));

        let (preferred_availability_zone, arn) = {
            let mut accounts = self.state.write();
            let state = accounts.get_or_create(&request.account_id);
            if !state.begin_cache_cluster_creation(&cache_cluster_id) {
                return Err(AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "CacheClusterAlreadyExists",
                    format!("CacheCluster {cache_cluster_id} already exists."),
                ));
            }

            if let Some(ref subnet_group_name) = cache_subnet_group_name {
                if !state.subnet_groups.contains_key(subnet_group_name) {
                    state.cancel_cache_cluster_creation(&cache_cluster_id);
                    return Err(AwsServiceError::aws_error(
                        StatusCode::NOT_FOUND,
                        "CacheSubnetGroupNotFoundFault",
                        format!("Cache subnet group {subnet_group_name} not found."),
                    ));
                }
            }

            if let Some(ref group_id) = replication_group_id {
                if engine == ENGINE_MEMCACHED {
                    state.cancel_cache_cluster_creation(&cache_cluster_id);
                    return Err(AwsServiceError::aws_error(
                        StatusCode::BAD_REQUEST,
                        "InvalidParameterValue",
                        "Replication groups are not supported for the memcached engine."
                            .to_string(),
                    ));
                }
                if !state.replication_groups.contains_key(group_id) {
                    state.cancel_cache_cluster_creation(&cache_cluster_id);
                    return Err(AwsServiceError::aws_error(
                        StatusCode::NOT_FOUND,
                        "ReplicationGroupNotFoundFault",
                        format!("ReplicationGroup {group_id} not found."),
                    ));
                }
            }

            let preferred_availability_zone =
                optional_query_param(request, "PreferredAvailabilityZone")
                    .unwrap_or_else(|| format!("{}a", state.region));
            let arn = format!(
                "arn:aws:elasticache:{}:{}:cluster:{}",
                state.region, state.account_id, cache_cluster_id
            );
            (preferred_availability_zone, arn)
        };

        let runtime = self.runtime.as_ref().ok_or_else(|| {
            self.state
                .write()
                .get_or_create(&request.account_id)
                .cancel_cache_cluster_creation(&cache_cluster_id);
            AwsServiceError::aws_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "InvalidParameterValue",
                "Docker/Podman is required for ElastiCache cache clusters but is not available"
                    .to_string(),
            )
        })?;

        let runtime_result = if engine == ENGINE_MEMCACHED {
            runtime.ensure_memcached(&cache_cluster_id).await
        } else {
            runtime.ensure_redis(&cache_cluster_id).await
        };
        let running = match runtime_result {
            Ok(r) => r,
            Err(e) => {
                self.state
                    .write()
                    .get_or_create(&request.account_id)
                    .cancel_cache_cluster_creation(&cache_cluster_id);
                return Err(runtime_error_to_service_error(e));
            }
        };

        let cluster = CacheCluster {
            cache_cluster_id: cache_cluster_id.clone(),
            cache_node_type,
            engine,
            engine_version,
            cache_cluster_status: "available".to_string(),
            num_cache_nodes,
            preferred_availability_zone,
            cache_subnet_group_name,
            auto_minor_version_upgrade,
            arn,
            created_at: chrono::Utc::now().to_rfc3339(),
            endpoint_address: "127.0.0.1".to_string(),
            endpoint_port: running.host_port,
            container_id: running.container_id,
            host_port: running.host_port,
            replication_group_id,
            cache_parameter_group_name,
            security_group_ids,
            log_delivery_configurations,
            transit_encryption_enabled,
            at_rest_encryption_enabled,
            auth_token_enabled,
            port,
            preferred_maintenance_window,
            preferred_availability_zones,
            notification_topic_arn,
            cache_security_group_names,
            snapshot_arns,
            snapshot_name,
            snapshot_retention_limit,
            snapshot_window,
            outpost_mode,
            preferred_outpost_arn,
            network_type,
            ip_discovery,
            az_mode,
            auth_token,
        };

        let xml = cache_cluster_xml(&cluster, true);
        {
            let mut accounts = self.state.write();
            let state = accounts.get_or_create(&request.account_id);
            state.finish_cache_cluster_creation(cluster.clone());
            if let Some(ref group_id) = cluster.replication_group_id {
                add_cluster_to_replication_group(state, group_id, &cluster.cache_cluster_id);
            }
        }

        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "CreateCacheCluster",
                ELASTICACHE_NS,
                &format!("<CacheCluster>{xml}</CacheCluster>"),
                &request.request_id,
            ),
        ))
    }

    fn describe_cache_clusters(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let cache_cluster_id = optional_query_param(request, "CacheClusterId");
        let show_cache_node_info =
            parse_optional_bool(optional_query_param(request, "ShowCacheNodeInfo").as_deref())?
                .unwrap_or(false);
        let max_records = optional_usize_param(request, "MaxRecords")?;
        let marker = optional_query_param(request, "Marker");

        let accounts = self.state.read();
        let empty = ElastiCacheState::new(&request.account_id, &request.region);
        let state = accounts.get(&request.account_id).unwrap_or(&empty);
        let clusters: Vec<&CacheCluster> = if let Some(ref cluster_id) = cache_cluster_id {
            match state.cache_clusters.get(cluster_id) {
                Some(cluster) => vec![cluster],
                None => {
                    return Err(AwsServiceError::aws_error(
                        StatusCode::NOT_FOUND,
                        "CacheClusterNotFound",
                        format!("CacheCluster {cluster_id} not found."),
                    ));
                }
            }
        } else {
            let mut clusters: Vec<&CacheCluster> = state.cache_clusters.values().collect();
            clusters.sort_by(|a, b| a.cache_cluster_id.cmp(&b.cache_cluster_id));
            clusters
        };

        let (page, next_marker) = paginate(&clusters, marker.as_deref(), max_records);
        let members_xml: String = page
            .iter()
            .map(|cluster| {
                format!(
                    "<CacheCluster>{}</CacheCluster>",
                    cache_cluster_xml(cluster, show_cache_node_info)
                )
            })
            .collect();
        let marker_xml = next_marker
            .map(|m| format!("<Marker>{}</Marker>", xml_escape(&m)))
            .unwrap_or_default();

        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "DescribeCacheClusters",
                ELASTICACHE_NS,
                &format!("<CacheClusters>{members_xml}</CacheClusters>{marker_xml}"),
                &request.request_id,
            ),
        ))
    }

    async fn delete_cache_cluster(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let cache_cluster_id = required_query_param(request, "CacheClusterId")?;

        let cluster = {
            let mut accounts = self.state.write();
            let state = accounts.get_or_create(&request.account_id);
            let cluster = state
                .cache_clusters
                .remove(&cache_cluster_id)
                .ok_or_else(|| {
                    AwsServiceError::aws_error(
                        StatusCode::NOT_FOUND,
                        "CacheClusterNotFound",
                        format!("CacheCluster {cache_cluster_id} not found."),
                    )
                })?;
            if let Some(ref group_id) = cluster.replication_group_id {
                remove_cluster_from_replication_group(state, group_id, &cluster.cache_cluster_id);
            }
            state.tags.remove(&cluster.arn);
            cluster
        };

        if let Some(ref runtime) = self.runtime {
            runtime.stop_container(&cache_cluster_id).await;
        }

        let mut deleted_cluster = cluster;
        deleted_cluster.cache_cluster_status = "deleting".to_string();
        let xml = cache_cluster_xml(&deleted_cluster, true);

        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "DeleteCacheCluster",
                ELASTICACHE_NS,
                &format!("<CacheCluster>{xml}</CacheCluster>"),
                &request.request_id,
            ),
        ))
    }

    async fn create_replication_group(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let replication_group_id = required_query_param(request, "ReplicationGroupId")?;
        let description = required_query_param(request, "ReplicationGroupDescription")?;
        let engine =
            optional_query_param(request, "Engine").unwrap_or_else(|| ENGINE_REDIS.to_string());
        validate_engine(&engine)?;
        reject_memcached_for(&engine, "Replication groups")?;
        let default_version = if engine == ENGINE_VALKEY {
            "8.0"
        } else {
            "7.1"
        };
        let engine_version = optional_query_param(request, "EngineVersion")
            .unwrap_or_else(|| default_version.to_string());
        let cache_node_type = optional_query_param(request, "CacheNodeType")
            .unwrap_or_else(|| "cache.t3.micro".to_string());
        let num_cache_clusters = match optional_query_param(request, "NumCacheClusters") {
            Some(v) => {
                let n = v.parse::<i32>().map_err(|_| {
                    AwsServiceError::aws_error(
                        StatusCode::BAD_REQUEST,
                        "InvalidParameterValue",
                        format!("Invalid value for NumCacheClusters: '{v}'"),
                    )
                })?;
                if n < 1 {
                    return Err(AwsServiceError::aws_error(
                        StatusCode::BAD_REQUEST,
                        "InvalidParameterValue",
                        format!("NumCacheClusters must be a positive integer, got {n}"),
                    ));
                }
                n
            }
            None => 1,
        };
        let automatic_failover = parse_optional_bool(
            optional_query_param(request, "AutomaticFailoverEnabled").as_deref(),
        )?
        .unwrap_or(false);
        let transit_encryption_enabled = parse_optional_bool(
            optional_query_param(request, "TransitEncryptionEnabled").as_deref(),
        )?
        .unwrap_or(false);
        let at_rest_encryption_enabled = parse_optional_bool(
            optional_query_param(request, "AtRestEncryptionEnabled").as_deref(),
        )?
        .unwrap_or(false);
        let multi_az_enabled =
            parse_optional_bool(optional_query_param(request, "MultiAZEnabled").as_deref())?
                .unwrap_or(false);
        let auth_token = optional_query_param(request, "AuthToken");
        let auth_token_enabled = auth_token.is_some();
        let kms_key_id = optional_query_param(request, "KmsKeyId");
        let user_group_ids = parse_query_list_param(request, "UserGroupIds", "UserGroupId");
        let num_node_groups = optional_query_param(request, "NumNodeGroups")
            .and_then(|v| v.parse::<i32>().ok())
            .unwrap_or(1);
        let replicas_per_node_group = optional_query_param(request, "ReplicasPerNodeGroup")
            .and_then(|v| v.parse::<i32>().ok());
        let data_tiering_enabled =
            parse_optional_bool(optional_query_param(request, "DataTieringEnabled").as_deref())?;
        let data_tiering =
            data_tiering_enabled.map(|b| if b { "enabled" } else { "disabled" }.to_string());
        let ip_discovery = optional_query_param(request, "IpDiscovery");
        // Default to ipv4 when unspecified, matching AWS's default network stack.
        let network_type =
            Some(optional_query_param(request, "NetworkType").unwrap_or_else(|| "ipv4".into()));
        let transit_encryption_mode = optional_query_param(request, "TransitEncryptionMode");
        let log_delivery_configurations = parse_log_delivery_configs(request);
        let notification_topic_arn = optional_query_param(request, "NotificationTopicArn");
        let cluster_mode = optional_query_param(request, "ClusterMode");
        let cluster_enabled = num_node_groups > 1
            || cluster_mode.as_deref() == Some("enabled")
            || cluster_mode.as_deref() == Some("compatible");
        // ElastiCache Redis defaults to 6379 when Port is omitted.
        let port = optional_query_param(request, "Port")
            .and_then(|v| v.parse::<u16>().ok())
            .unwrap_or(6379);
        // Reserve the ID under a write lock before starting the container.
        {
            let mut accounts = self.state.write();
            let state = accounts.get_or_create(&request.account_id);
            if !state.begin_replication_group_creation(&replication_group_id) {
                return Err(AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "ReplicationGroupAlreadyExistsFault",
                    format!("ReplicationGroup {replication_group_id} already exists."),
                ));
            }
        }

        let runtime = self.runtime.as_ref().ok_or_else(|| {
            self.state
                .write()
                .get_or_create(&request.account_id)
                .cancel_replication_group_creation(&replication_group_id);
            AwsServiceError::aws_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "InvalidParameterValue",
                "Docker/Podman is required for ElastiCache replication groups but is not available"
                    .to_string(),
            )
        })?;

        let running = match runtime.ensure_redis(&replication_group_id).await {
            Ok(r) => r,
            Err(e) => {
                self.state
                    .write()
                    .get_or_create(&request.account_id)
                    .cancel_replication_group_creation(&replication_group_id);
                return Err(runtime_error_to_service_error(e));
            }
        };

        let member_clusters: Vec<String> = (1..=num_cache_clusters)
            .map(|i| format!("{replication_group_id}-{i:03}"))
            .collect();

        let (arn, region) = {
            let accounts = self.state.read();
            let empty = ElastiCacheState::new(&request.account_id, &request.region);
            let state = accounts.get(&request.account_id).unwrap_or(&empty);
            let arn = format!(
                "arn:aws:elasticache:{}:{}:replicationgroup:{}",
                state.region, state.account_id, replication_group_id
            );
            (arn, state.region.clone())
        };

        let group = ReplicationGroup {
            replication_group_id: replication_group_id.clone(),
            description,
            global_replication_group_id: None,
            global_replication_group_role: None,
            status: "available".to_string(),
            cache_node_type,
            engine,
            engine_version,
            num_cache_clusters,
            automatic_failover_enabled: automatic_failover,
            endpoint_address: "127.0.0.1".to_string(),
            endpoint_port: running.host_port,
            arn,
            created_at: chrono::Utc::now().to_rfc3339(),
            container_id: running.container_id,
            host_port: running.host_port,
            member_clusters,
            snapshot_retention_limit: 0,
            snapshot_window: "05:00-09:00".to_string(),
            transit_encryption_enabled,
            at_rest_encryption_enabled,
            cluster_enabled,
            kms_key_id,
            auth_token_enabled,
            user_group_ids,
            multi_az_enabled,
            log_delivery_configurations,
            data_tiering,
            ip_discovery,
            network_type,
            transit_encryption_mode,
            num_node_groups,
            configuration_endpoint_address: if cluster_enabled {
                Some("127.0.0.1".to_string())
            } else {
                None
            },
            configuration_endpoint_port: if cluster_enabled {
                Some(running.host_port)
            } else {
                None
            },
            replicas_per_node_group,
            auth_token,
            port,
            notification_topic_arn,
            cluster_mode,
            data_tiering_enabled,
            notification_topic_status: None,
        };

        let xml = replication_group_xml(&group, &region);
        self.state
            .write()
            .get_or_create(&request.account_id)
            .finish_replication_group_creation(group);

        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "CreateReplicationGroup",
                ELASTICACHE_NS,
                &format!("<ReplicationGroup>{xml}</ReplicationGroup>"),
                &request.request_id,
            ),
        ))
    }

    fn create_global_replication_group(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let suffix = required_query_param(request, "GlobalReplicationGroupIdSuffix")?;
        let primary_replication_group_id =
            required_query_param(request, "PrimaryReplicationGroupId")?;
        let description =
            optional_query_param(request, "GlobalReplicationGroupDescription").unwrap_or_default();

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request.account_id);
        let region = state.region.clone();
        let account_id = state.account_id.clone();
        let global_replication_group_id = global_replication_group_id(&region, suffix.as_str());
        if state
            .global_replication_groups
            .contains_key(&global_replication_group_id)
        {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "GlobalReplicationGroupAlreadyExistsFault",
                format!("GlobalReplicationGroup {global_replication_group_id} already exists."),
            ));
        }

        let primary_group = state
            .replication_groups
            .get_mut(&primary_replication_group_id)
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::NOT_FOUND,
                    "ReplicationGroupNotFoundFault",
                    format!("ReplicationGroup {primary_replication_group_id} not found."),
                )
            })?;

        if primary_group.global_replication_group_id.is_some() {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidReplicationGroupStateFault",
                format!(
                    "ReplicationGroup {primary_replication_group_id} is already associated with a GlobalReplicationGroup."
                ),
            ));
        }

        primary_group.global_replication_group_id = Some(global_replication_group_id.clone());
        primary_group.global_replication_group_role = Some("primary".to_string());

        let group = GlobalReplicationGroup {
            global_replication_group_id: global_replication_group_id.clone(),
            global_replication_group_description: description,
            status: "available".to_string(),
            cache_node_type: primary_group.cache_node_type.clone(),
            engine: primary_group.engine.clone(),
            engine_version: primary_group.engine_version.clone(),
            members: vec![GlobalReplicationGroupMember {
                replication_group_id: primary_group.replication_group_id.clone(),
                replication_group_region: region.clone(),
                role: "primary".to_string(),
                automatic_failover: primary_group.automatic_failover_enabled,
                status: "associated".to_string(),
            }],
            cluster_enabled: false,
            arn: format!(
                "arn:aws:elasticache:{}:{}:globalreplicationgroup:{}",
                region, account_id, global_replication_group_id
            ),
        };

        let xml = global_replication_group_xml(&group, true);
        state
            .global_replication_groups
            .insert(global_replication_group_id, group);

        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "CreateGlobalReplicationGroup",
                ELASTICACHE_NS,
                &format!("<GlobalReplicationGroup>{xml}</GlobalReplicationGroup>"),
                &request.request_id,
            ),
        ))
    }

    fn describe_global_replication_groups(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let global_replication_group_id = optional_query_param(request, "GlobalReplicationGroupId");
        let max_records = optional_usize_param(request, "MaxRecords")?;
        let marker = optional_query_param(request, "Marker");
        let show_member_info =
            parse_optional_bool(optional_query_param(request, "ShowMemberInfo").as_deref())?
                .unwrap_or(false);

        let accounts = self.state.read();
        let empty = ElastiCacheState::new(&request.account_id, &request.region);
        let state = accounts.get(&request.account_id).unwrap_or(&empty);
        let groups: Vec<&GlobalReplicationGroup> = if let Some(ref global_replication_group_id) =
            global_replication_group_id
        {
            match state
                .global_replication_groups
                .get(global_replication_group_id)
            {
                Some(group) => vec![group],
                None => {
                    return Err(AwsServiceError::aws_error(
                        StatusCode::NOT_FOUND,
                        "GlobalReplicationGroupNotFoundFault",
                        format!("GlobalReplicationGroup {global_replication_group_id} not found."),
                    ));
                }
            }
        } else {
            let mut groups: Vec<&GlobalReplicationGroup> =
                state.global_replication_groups.values().collect();
            groups.sort_by(|a, b| {
                a.global_replication_group_id
                    .cmp(&b.global_replication_group_id)
            });
            groups
        };

        let (page, next_marker) = paginate(&groups, marker.as_deref(), max_records);
        let groups_xml: String = page
            .iter()
            .map(|group| {
                format!(
                    "<GlobalReplicationGroup>{}</GlobalReplicationGroup>",
                    global_replication_group_xml(group, show_member_info)
                )
            })
            .collect();
        let marker_xml = next_marker
            .map(|m| format!("<Marker>{}</Marker>", xml_escape(&m)))
            .unwrap_or_default();

        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "DescribeGlobalReplicationGroups",
                ELASTICACHE_NS,
                &format!(
                    "<GlobalReplicationGroups>{groups_xml}</GlobalReplicationGroups>{marker_xml}"
                ),
                &request.request_id,
            ),
        ))
    }

    fn describe_replication_groups(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let group_id = optional_query_param(request, "ReplicationGroupId");
        let max_records = optional_usize_param(request, "MaxRecords")?;
        let marker = optional_query_param(request, "Marker");

        let accounts = self.state.read();
        let empty = ElastiCacheState::new(&request.account_id, &request.region);
        let state = accounts.get(&request.account_id).unwrap_or(&empty);
        let region = state.region.clone();

        let groups: Vec<&ReplicationGroup> = if let Some(ref id) = group_id {
            match state.replication_groups.get(id) {
                Some(g) => vec![g],
                None => {
                    return Err(AwsServiceError::aws_error(
                        StatusCode::NOT_FOUND,
                        "ReplicationGroupNotFoundFault",
                        format!("ReplicationGroup {id} not found."),
                    ));
                }
            }
        } else {
            let mut groups: Vec<&ReplicationGroup> = state.replication_groups.values().collect();
            groups.sort_by(|a, b| a.replication_group_id.cmp(&b.replication_group_id));
            groups
        };

        let (page, next_marker) = paginate(&groups, marker.as_deref(), max_records);

        let members_xml: String = page
            .iter()
            .map(|g| {
                format!(
                    "<ReplicationGroup>{}</ReplicationGroup>",
                    replication_group_xml(g, &region)
                )
            })
            .collect();
        let marker_xml = next_marker
            .map(|m| format!("<Marker>{}</Marker>", xml_escape(&m)))
            .unwrap_or_default();

        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "DescribeReplicationGroups",
                ELASTICACHE_NS,
                &format!("<ReplicationGroups>{members_xml}</ReplicationGroups>{marker_xml}"),
                &request.request_id,
            ),
        ))
    }

    fn delete_global_replication_group(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let global_replication_group_id =
            required_query_param(request, "GlobalReplicationGroupId")?;
        let retain_primary = parse_required_bool(request, "RetainPrimaryReplicationGroup")?;

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request.account_id);
        let mut group = state
            .global_replication_groups
            .remove(&global_replication_group_id)
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::NOT_FOUND,
                    "GlobalReplicationGroupNotFoundFault",
                    format!("GlobalReplicationGroup {global_replication_group_id} not found."),
                )
            })?;

        for member in &group.members {
            if !retain_primary && member.role == "primary" {
                // Delete the primary replication group when RetainPrimaryReplicationGroup=false
                if let Some(rg) = state
                    .replication_groups
                    .remove(&member.replication_group_id)
                {
                    state.tags.remove(&rg.arn);
                }
            } else if let Some(replication_group) = state
                .replication_groups
                .get_mut(&member.replication_group_id)
            {
                replication_group.global_replication_group_id = None;
                replication_group.global_replication_group_role = None;
            }
        }

        group.status = "deleting".to_string();
        let xml = global_replication_group_xml(&group, true);

        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "DeleteGlobalReplicationGroup",
                ELASTICACHE_NS,
                &format!("<GlobalReplicationGroup>{xml}</GlobalReplicationGroup>"),
                &request.request_id,
            ),
        ))
    }

    async fn delete_replication_group(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let replication_group_id = required_query_param(request, "ReplicationGroupId")?;

        let group = {
            let mut accounts = self.state.write();
            let state = accounts.get_or_create(&request.account_id);
            let g = state
                .replication_groups
                .remove(&replication_group_id)
                .ok_or_else(|| {
                    AwsServiceError::aws_error(
                        StatusCode::NOT_FOUND,
                        "ReplicationGroupNotFoundFault",
                        format!("ReplicationGroup {replication_group_id} not found."),
                    )
                })?;
            state.tags.remove(&g.arn);
            g
        };

        if let Some(ref runtime) = self.runtime {
            runtime.stop_container(&replication_group_id).await;
        }

        let region = self.state.read().region().to_string();
        let mut deleted_group = group;
        deleted_group.status = "deleting".to_string();
        let xml = replication_group_xml(&deleted_group, &region);

        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "DeleteReplicationGroup",
                ELASTICACHE_NS,
                &format!("<ReplicationGroup>{xml}</ReplicationGroup>"),
                &request.request_id,
            ),
        ))
    }

    async fn create_serverless_cache(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let serverless_cache_name = required_query_param(request, "ServerlessCacheName")?;
        let engine = required_query_param(request, "Engine")?;
        validate_serverless_engine(&engine)?;

        let description = optional_query_param(request, "Description").unwrap_or_default();
        let major_engine_version = optional_query_param(request, "MajorEngineVersion")
            .unwrap_or_else(|| default_major_engine_version(&engine).to_string());
        let full_engine_version = default_full_engine_version(&engine, &major_engine_version)?;
        let cache_usage_limits = parse_cache_usage_limits(request)?;
        let security_group_ids =
            parse_query_list_param(request, "SecurityGroupIds", "SecurityGroupId");
        let subnet_ids = parse_query_list_param(request, "SubnetIds", "SubnetId");
        let kms_key_id = optional_query_param(request, "KmsKeyId");
        let user_group_id = optional_query_param(request, "UserGroupId");
        let snapshot_retention_limit =
            optional_non_negative_i32_param(request, "SnapshotRetentionLimit")?;
        let daily_snapshot_time = optional_query_param(request, "DailySnapshotTime");
        let tags = parse_tags(request)?;

        let (arn, endpoint_address) = {
            let mut accounts = self.state.write();
            let state = accounts.get_or_create(&request.account_id);
            if !state.begin_serverless_cache_creation(&serverless_cache_name) {
                return Err(AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "ServerlessCacheAlreadyExistsFault",
                    format!("ServerlessCache {serverless_cache_name} already exists."),
                ));
            }

            if let Some(ref group_id) = user_group_id {
                let user_group_status = match state.user_groups.get(group_id) {
                    Some(user_group) => user_group.status.clone(),
                    None => {
                        state.cancel_serverless_cache_creation(&serverless_cache_name);
                        return Err(AwsServiceError::aws_error(
                            StatusCode::NOT_FOUND,
                            "UserGroupNotFoundFault",
                            format!("User group {group_id} not found."),
                        ));
                    }
                };
                if user_group_status != "active" {
                    state.cancel_serverless_cache_creation(&serverless_cache_name);
                    return Err(AwsServiceError::aws_error(
                        StatusCode::BAD_REQUEST,
                        "InvalidUserGroupState",
                        format!("User group {group_id} is not in active state."),
                    ));
                }
            }

            let arn = format!(
                "arn:aws:elasticache:{}:{}:serverlesscache:{}",
                state.region, state.account_id, serverless_cache_name
            );
            (arn, "127.0.0.1".to_string())
        };

        let runtime = self.runtime.as_ref().ok_or_else(|| {
            self.state
                .write()
                .get_or_create(&request.account_id)
                .cancel_serverless_cache_creation(&serverless_cache_name);
            AwsServiceError::aws_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "InvalidParameterValue",
                "Docker/Podman is required for ElastiCache serverless caches but is not available"
                    .to_string(),
            )
        })?;

        let running = match runtime.ensure_redis(&serverless_cache_name).await {
            Ok(r) => r,
            Err(e) => {
                self.state
                    .write()
                    .get_or_create(&request.account_id)
                    .cancel_serverless_cache_creation(&serverless_cache_name);
                return Err(runtime_error_to_service_error(e));
            }
        };

        let endpoint = ServerlessCacheEndpoint {
            address: endpoint_address.clone(),
            port: running.host_port,
        };
        let reader_endpoint = ServerlessCacheEndpoint {
            address: endpoint_address,
            port: running.host_port,
        };
        let cache = ServerlessCache {
            serverless_cache_name: serverless_cache_name.clone(),
            description,
            engine,
            major_engine_version,
            full_engine_version,
            status: "available".to_string(),
            endpoint,
            reader_endpoint,
            arn: arn.clone(),
            created_at: chrono::Utc::now().to_rfc3339(),
            cache_usage_limits,
            security_group_ids,
            subnet_ids,
            kms_key_id,
            user_group_id,
            snapshot_retention_limit,
            daily_snapshot_time,
            container_id: running.container_id,
            host_port: running.host_port,
        };

        let xml = serverless_cache_xml(&cache);
        {
            let mut accounts = self.state.write();
            let state = accounts.get_or_create(&request.account_id);
            state.finish_serverless_cache_creation(cache.clone());
            if !tags.is_empty() {
                merge_tags(state.tags.entry(arn).or_default(), &tags);
            }
        }

        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "CreateServerlessCache",
                ELASTICACHE_NS,
                &format!("<ServerlessCache>{xml}</ServerlessCache>"),
                &request.request_id,
            ),
        ))
    }

    fn describe_serverless_caches(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let serverless_cache_name = optional_query_param(request, "ServerlessCacheName");
        let max_results = optional_usize_param(request, "MaxResults")?;
        let next_token = optional_query_param(request, "NextToken");

        let accounts = self.state.read();
        let empty = ElastiCacheState::new(&request.account_id, &request.region);
        let state = accounts.get(&request.account_id).unwrap_or(&empty);
        let caches: Vec<&ServerlessCache> = if let Some(ref name) = serverless_cache_name {
            match state.serverless_caches.get(name) {
                Some(cache) => vec![cache],
                None => {
                    return Err(AwsServiceError::aws_error(
                        StatusCode::NOT_FOUND,
                        "ServerlessCacheNotFoundFault",
                        format!("ServerlessCache {name} not found."),
                    ));
                }
            }
        } else {
            let mut caches: Vec<&ServerlessCache> = state.serverless_caches.values().collect();
            caches.sort_by(|a, b| a.serverless_cache_name.cmp(&b.serverless_cache_name));
            caches
        };

        let (page, next_token) = paginate(&caches, next_token.as_deref(), max_results);
        let members_xml: String = page
            .iter()
            .map(|cache| format!("<member>{}</member>", serverless_cache_xml(cache)))
            .collect();
        let next_token_xml = next_token
            .map(|token| format!("<NextToken>{}</NextToken>", xml_escape(&token)))
            .unwrap_or_default();

        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "DescribeServerlessCaches",
                ELASTICACHE_NS,
                &format!("<ServerlessCaches>{members_xml}</ServerlessCaches>{next_token_xml}"),
                &request.request_id,
            ),
        ))
    }

    async fn delete_serverless_cache(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let serverless_cache_name = required_query_param(request, "ServerlessCacheName")?;

        let cache = {
            let mut accounts = self.state.write();
            let state = accounts.get_or_create(&request.account_id);
            let cache = state
                .serverless_caches
                .remove(&serverless_cache_name)
                .ok_or_else(|| {
                    AwsServiceError::aws_error(
                        StatusCode::NOT_FOUND,
                        "ServerlessCacheNotFoundFault",
                        format!("ServerlessCache {serverless_cache_name} not found."),
                    )
                })?;
            state.tags.remove(&cache.arn);
            cache
        };

        if let Some(ref runtime) = self.runtime {
            runtime.stop_container(&serverless_cache_name).await;
        }

        let mut deleted = cache;
        deleted.status = "deleting".to_string();
        let xml = serverless_cache_xml(&deleted);

        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "DeleteServerlessCache",
                ELASTICACHE_NS,
                &format!("<ServerlessCache>{xml}</ServerlessCache>"),
                &request.request_id,
            ),
        ))
    }

    fn modify_serverless_cache(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let serverless_cache_name = required_query_param(request, "ServerlessCacheName")?;
        let description = optional_query_param(request, "Description");
        let cache_usage_limits = parse_cache_usage_limits(request)?;
        let security_group_ids =
            parse_query_list_param(request, "SecurityGroupIds", "SecurityGroupId");
        let user_group_id = optional_query_param(request, "UserGroupId");
        let snapshot_retention_limit =
            optional_non_negative_i32_param(request, "SnapshotRetentionLimit")?;
        let daily_snapshot_time = optional_query_param(request, "DailySnapshotTime");

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request.account_id);

        if let Some(ref group_id) = user_group_id {
            let user_group = state.user_groups.get(group_id).ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::NOT_FOUND,
                    "UserGroupNotFoundFault",
                    format!("User group {group_id} not found."),
                )
            })?;
            if user_group.status != "active" {
                return Err(AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidUserGroupState",
                    format!("User group {group_id} is not in active state."),
                ));
            }
        }

        let cache = state
            .serverless_caches
            .get_mut(&serverless_cache_name)
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::NOT_FOUND,
                    "ServerlessCacheNotFoundFault",
                    format!("ServerlessCache {serverless_cache_name} not found."),
                )
            })?;

        if let Some(description) = description {
            cache.description = description;
        }
        if cache_usage_limits.is_some() {
            cache.cache_usage_limits = cache_usage_limits;
        }
        if !security_group_ids.is_empty() {
            cache.security_group_ids = security_group_ids;
        }
        if let Some(user_group_id) = user_group_id {
            cache.user_group_id = Some(user_group_id);
        }
        if let Some(snapshot_retention_limit) = snapshot_retention_limit {
            cache.snapshot_retention_limit = Some(snapshot_retention_limit);
        }
        if let Some(daily_snapshot_time) = daily_snapshot_time {
            cache.daily_snapshot_time = Some(daily_snapshot_time);
        }

        let xml = serverless_cache_xml(cache);
        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "ModifyServerlessCache",
                ELASTICACHE_NS,
                &format!("<ServerlessCache>{xml}</ServerlessCache>"),
                &request.request_id,
            ),
        ))
    }

    fn create_serverless_cache_snapshot(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let serverless_cache_name = required_query_param(request, "ServerlessCacheName")?;
        let serverless_cache_snapshot_name =
            required_query_param(request, "ServerlessCacheSnapshotName")?;
        let kms_key_id = optional_query_param(request, "KmsKeyId");
        let tags = parse_tags(request)?;

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request.account_id);
        if state
            .serverless_cache_snapshots
            .contains_key(&serverless_cache_snapshot_name)
        {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ServerlessCacheSnapshotAlreadyExistsFault",
                format!("ServerlessCacheSnapshot {serverless_cache_snapshot_name} already exists."),
            ));
        }

        let cache = state
            .serverless_caches
            .get(&serverless_cache_name)
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::NOT_FOUND,
                    "ServerlessCacheNotFoundFault",
                    format!("ServerlessCache {serverless_cache_name} not found."),
                )
            })?;

        let arn = format!(
            "arn:aws:elasticache:{}:{}:serverlesssnapshot:{}",
            state.region, state.account_id, serverless_cache_snapshot_name
        );
        let snapshot = ServerlessCacheSnapshot {
            serverless_cache_snapshot_name: serverless_cache_snapshot_name.clone(),
            arn: arn.clone(),
            kms_key_id: kms_key_id.or_else(|| cache.kms_key_id.clone()),
            snapshot_type: "manual".to_string(),
            status: "available".to_string(),
            create_time: chrono::Utc::now().to_rfc3339(),
            expiry_time: None,
            bytes_used_for_cache: None,
            serverless_cache_name: cache.serverless_cache_name.clone(),
            engine: cache.engine.clone(),
            major_engine_version: cache.major_engine_version.clone(),
        };

        let xml = serverless_cache_snapshot_xml(&snapshot);
        state.tags.insert(arn.clone(), Vec::new());
        if !tags.is_empty() {
            merge_tags(state.tags.entry(arn).or_default(), &tags);
        }
        state
            .serverless_cache_snapshots
            .insert(serverless_cache_snapshot_name, snapshot);

        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "CreateServerlessCacheSnapshot",
                ELASTICACHE_NS,
                &format!("<ServerlessCacheSnapshot>{xml}</ServerlessCacheSnapshot>"),
                &request.request_id,
            ),
        ))
    }

    fn describe_serverless_cache_snapshots(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let serverless_cache_name = optional_query_param(request, "ServerlessCacheName");
        let serverless_cache_snapshot_name =
            optional_query_param(request, "ServerlessCacheSnapshotName");
        let snapshot_type = optional_query_param(request, "SnapshotType");
        let max_results = optional_usize_param(request, "MaxResults")?;
        let next_token = optional_query_param(request, "NextToken");

        let accounts = self.state.read();
        let empty = ElastiCacheState::new(&request.account_id, &request.region);
        let state = accounts.get(&request.account_id).unwrap_or(&empty);
        let snapshots: Vec<&ServerlessCacheSnapshot> =
            if let Some(ref snapshot_name) = serverless_cache_snapshot_name {
                match state.serverless_cache_snapshots.get(snapshot_name) {
                    Some(snapshot) => vec![snapshot],
                    None => {
                        return Err(AwsServiceError::aws_error(
                            StatusCode::NOT_FOUND,
                            "ServerlessCacheSnapshotNotFoundFault",
                            format!("ServerlessCacheSnapshot {snapshot_name} not found."),
                        ));
                    }
                }
            } else {
                if let Some(ref cache_name) = serverless_cache_name {
                    if !state.serverless_caches.contains_key(cache_name) {
                        return Err(AwsServiceError::aws_error(
                            StatusCode::NOT_FOUND,
                            "ServerlessCacheNotFoundFault",
                            format!("ServerlessCache {cache_name} not found."),
                        ));
                    }
                }

                let mut snapshots: Vec<&ServerlessCacheSnapshot> = state
                    .serverless_cache_snapshots
                    .values()
                    .filter(|snapshot| {
                        serverless_cache_name
                            .as_ref()
                            .is_none_or(|name| snapshot.serverless_cache_name == *name)
                    })
                    .filter(|snapshot| {
                        snapshot_type
                            .as_ref()
                            .is_none_or(|value| snapshot.snapshot_type == *value)
                    })
                    .collect();
                snapshots.sort_by(|a, b| {
                    a.serverless_cache_snapshot_name
                        .cmp(&b.serverless_cache_snapshot_name)
                });
                snapshots
            };

        let (page, next_token) = paginate(&snapshots, next_token.as_deref(), max_results);
        let members_xml: String = page
            .iter()
            .map(|snapshot| {
                format!(
                    "<ServerlessCacheSnapshot>{}</ServerlessCacheSnapshot>",
                    serverless_cache_snapshot_xml(snapshot)
                )
            })
            .collect();
        let next_token_xml = next_token
            .map(|token| format!("<NextToken>{}</NextToken>", xml_escape(&token)))
            .unwrap_or_default();

        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "DescribeServerlessCacheSnapshots", ELASTICACHE_NS,
                &format!(
                    "<ServerlessCacheSnapshots>{members_xml}</ServerlessCacheSnapshots>{next_token_xml}"
                ),
                &request.request_id,
            ),
        ))
    }

    fn delete_serverless_cache_snapshot(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let serverless_cache_snapshot_name =
            required_query_param(request, "ServerlessCacheSnapshotName")?;

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request.account_id);
        let mut snapshot = state
            .serverless_cache_snapshots
            .remove(&serverless_cache_snapshot_name)
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::NOT_FOUND,
                    "ServerlessCacheSnapshotNotFoundFault",
                    format!("ServerlessCacheSnapshot {serverless_cache_snapshot_name} not found."),
                )
            })?;
        state.tags.remove(&snapshot.arn);

        snapshot.status = "deleting".to_string();
        let xml = serverless_cache_snapshot_xml(&snapshot);

        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "DeleteServerlessCacheSnapshot",
                ELASTICACHE_NS,
                &format!("<ServerlessCacheSnapshot>{xml}</ServerlessCacheSnapshot>"),
                &request.request_id,
            ),
        ))
    }

    fn create_snapshot(&self, request: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let snapshot_name = required_query_param(request, "SnapshotName")?;
        let replication_group_id = optional_query_param(request, "ReplicationGroupId");
        let cache_cluster_id = optional_query_param(request, "CacheClusterId");

        if replication_group_id.is_none() && cache_cluster_id.is_none() {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidParameterCombination",
                "At least one of ReplicationGroupId or CacheClusterId must be specified."
                    .to_string(),
            ));
        }

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request.account_id);

        if state.snapshots.contains_key(&snapshot_name) {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "SnapshotAlreadyExistsFault",
                format!("Snapshot {snapshot_name} already exists."),
            ));
        }

        // Resolve the replication group: either directly by ID or via CacheClusterId
        let group_id = if let Some(ref rg_id) = replication_group_id {
            rg_id.clone()
        } else {
            let cluster_id = cache_cluster_id.as_ref().unwrap();
            if let Some(cluster) = state.cache_clusters.get(cluster_id) {
                if let Some(group_id) = cluster.replication_group_id.clone() {
                    group_id
                } else {
                    return Err(AwsServiceError::aws_error(
                        StatusCode::BAD_REQUEST,
                        "InvalidParameterCombination",
                        format!(
                            "CacheCluster {cluster_id} is not associated with a replication group."
                        ),
                    ));
                }
            } else {
                // CacheClusterId may also map to a member cluster like "rg-001", find parent group
                state
                    .replication_groups
                    .values()
                    .find(|g| g.member_clusters.contains(cluster_id))
                    .map(|g| g.replication_group_id.clone())
                    .ok_or_else(|| {
                        AwsServiceError::aws_error(
                            StatusCode::NOT_FOUND,
                            "CacheClusterNotFound",
                            format!("CacheCluster {cluster_id} not found."),
                        )
                    })?
            }
        };

        let group = state.replication_groups.get(&group_id).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "ReplicationGroupNotFoundFault",
                format!("ReplicationGroup {group_id} not found."),
            )
        })?;

        let arn = format!(
            "arn:aws:elasticache:{}:{}:snapshot:{}",
            state.region, state.account_id, snapshot_name
        );

        let snapshot = CacheSnapshot {
            snapshot_name: snapshot_name.clone(),
            replication_group_id: group.replication_group_id.clone(),
            replication_group_description: group.description.clone(),
            snapshot_status: "available".to_string(),
            cache_node_type: group.cache_node_type.clone(),
            engine: group.engine.clone(),
            engine_version: group.engine_version.clone(),
            num_cache_clusters: group.num_cache_clusters,
            arn: arn.clone(),
            created_at: chrono::Utc::now().to_rfc3339(),
            snapshot_source: "manual".to_string(),
        };

        let xml = snapshot_xml(&snapshot);
        state.tags.insert(arn, Vec::new());
        state.snapshots.insert(snapshot_name, snapshot);

        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "CreateSnapshot",
                ELASTICACHE_NS,
                &format!("<Snapshot>{xml}</Snapshot>"),
                &request.request_id,
            ),
        ))
    }

    fn describe_snapshots(&self, request: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let snapshot_name = optional_query_param(request, "SnapshotName");
        let replication_group_id = optional_query_param(request, "ReplicationGroupId");
        let cache_cluster_id = optional_query_param(request, "CacheClusterId");
        let max_records = optional_usize_param(request, "MaxRecords")?;
        let marker = optional_query_param(request, "Marker");

        let accounts = self.state.read();
        let empty = ElastiCacheState::new(&request.account_id, &request.region);
        let state = accounts.get(&request.account_id).unwrap_or(&empty);

        let snapshots: Vec<&CacheSnapshot> = if let Some(ref name) = snapshot_name {
            match state.snapshots.get(name) {
                Some(s) => vec![s],
                None => {
                    return Err(AwsServiceError::aws_error(
                        StatusCode::NOT_FOUND,
                        "SnapshotNotFoundFault",
                        format!("Snapshot {name} not found."),
                    ));
                }
            }
        } else {
            let mut snaps: Vec<&CacheSnapshot> = state
                .snapshots
                .values()
                .filter(|s| {
                    replication_group_id
                        .as_ref()
                        .is_none_or(|id| s.replication_group_id == *id)
                })
                .filter(|s| {
                    cache_cluster_id.as_ref().is_none_or(|cluster_id| {
                        state.cache_clusters.get(cluster_id).is_some_and(|cluster| {
                            cluster.replication_group_id.as_deref() == Some(&s.replication_group_id)
                        }) || state
                            .replication_groups
                            .get(&s.replication_group_id)
                            .is_some_and(|g| g.member_clusters.contains(cluster_id))
                    })
                })
                .collect();
            snaps.sort_by(|a, b| a.snapshot_name.cmp(&b.snapshot_name));
            snaps
        };

        let (page, next_marker) = paginate(&snapshots, marker.as_deref(), max_records);

        let members_xml: String = page
            .iter()
            .map(|s| format!("<Snapshot>{}</Snapshot>", snapshot_xml(s)))
            .collect();
        let marker_xml = next_marker
            .map(|m| format!("<Marker>{}</Marker>", xml_escape(&m)))
            .unwrap_or_default();

        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "DescribeSnapshots",
                ELASTICACHE_NS,
                &format!("<Snapshots>{members_xml}</Snapshots>{marker_xml}"),
                &request.request_id,
            ),
        ))
    }

    fn delete_snapshot(&self, request: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let snapshot_name = required_query_param(request, "SnapshotName")?;

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request.account_id);
        let mut snapshot = state.snapshots.remove(&snapshot_name).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "SnapshotNotFoundFault",
                format!("Snapshot {snapshot_name} not found."),
            )
        })?;
        state.tags.remove(&snapshot.arn);

        snapshot.snapshot_status = "deleting".to_string();
        let xml = snapshot_xml(&snapshot);

        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "DeleteSnapshot",
                ELASTICACHE_NS,
                &format!("<Snapshot>{xml}</Snapshot>"),
                &request.request_id,
            ),
        ))
    }

    fn modify_replication_group(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let replication_group_id = required_query_param(request, "ReplicationGroupId")?;

        let new_description = optional_query_param(request, "ReplicationGroupDescription");
        let new_cache_node_type = optional_query_param(request, "CacheNodeType");
        let new_engine_version = optional_query_param(request, "EngineVersion");
        let new_automatic_failover = parse_optional_bool(
            optional_query_param(request, "AutomaticFailoverEnabled").as_deref(),
        )?;
        let new_snapshot_retention_limit = optional_query_param(request, "SnapshotRetentionLimit")
            .map(|v| {
                let val = v.parse::<i32>().map_err(|_| {
                    AwsServiceError::aws_error(
                        StatusCode::BAD_REQUEST,
                        "InvalidParameterValue",
                        format!("Invalid value for SnapshotRetentionLimit: '{v}'"),
                    )
                })?;
                if val < 0 {
                    return Err(AwsServiceError::aws_error(
                        StatusCode::BAD_REQUEST,
                        "InvalidParameterValue",
                        format!("SnapshotRetentionLimit must be non-negative, got {val}"),
                    ));
                }
                Ok(val)
            })
            .transpose()?;
        let new_snapshot_window = optional_query_param(request, "SnapshotWindow");
        let user_group_ids_to_add =
            parse_member_list(&request.query_params, "UserGroupIdsToAdd", "member");
        let user_group_ids_to_remove =
            parse_member_list(&request.query_params, "UserGroupIdsToRemove", "member");
        let new_auth_token = optional_query_param(request, "AuthToken");
        let new_auth_token_strategy = optional_query_param(request, "AuthTokenUpdateStrategy");
        let new_transit_encryption_enabled = parse_optional_bool(
            optional_query_param(request, "TransitEncryptionEnabled").as_deref(),
        )?;
        let new_multi_az_enabled =
            parse_optional_bool(optional_query_param(request, "MultiAZEnabled").as_deref())?;
        let remove_user_groups =
            parse_optional_bool(optional_query_param(request, "RemoveUserGroups").as_deref())?;
        let new_log_delivery_configurations = parse_log_delivery_configs(request);
        let has_log_delivery_input = !new_log_delivery_configurations.is_empty()
            || request.query_params.keys().any(|k| {
                k.starts_with("LogDeliveryConfigurations.LogDeliveryConfigurationRequest.")
            });
        let new_ip_discovery = optional_query_param(request, "IpDiscovery");
        let new_network_type = optional_query_param(request, "NetworkType");
        let new_notification_topic_arn = optional_query_param(request, "NotificationTopicArn");
        let new_notification_topic_status =
            optional_query_param(request, "NotificationTopicStatus");

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request.account_id);

        let group = state
            .replication_groups
            .get_mut(&replication_group_id)
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::NOT_FOUND,
                    "ReplicationGroupNotFoundFault",
                    format!("ReplicationGroup {replication_group_id} not found."),
                )
            })?;

        if let Some(desc) = new_description {
            group.description = desc;
        }
        if let Some(node_type) = new_cache_node_type {
            group.cache_node_type = node_type;
        }
        if let Some(version) = new_engine_version {
            group.engine_version = version;
        }
        if let Some(af) = new_automatic_failover {
            group.automatic_failover_enabled = af;
        }
        if let Some(limit) = new_snapshot_retention_limit {
            group.snapshot_retention_limit = limit;
        }
        if let Some(window) = new_snapshot_window {
            group.snapshot_window = window;
        }
        if let Some(transit) = new_transit_encryption_enabled {
            group.transit_encryption_enabled = transit;
        }
        if let Some(multi_az) = new_multi_az_enabled {
            group.multi_az_enabled = multi_az;
        }
        if let Some(ip_discovery) = new_ip_discovery {
            group.ip_discovery = Some(ip_discovery);
        }
        if let Some(network_type) = new_network_type {
            group.network_type = Some(network_type);
        }
        if let Some(arn) = new_notification_topic_arn {
            group.notification_topic_arn = Some(arn);
        }
        if let Some(status) = new_notification_topic_status {
            group.notification_topic_status = Some(status);
        }
        if has_log_delivery_input {
            group.log_delivery_configurations = new_log_delivery_configurations;
        }
        if remove_user_groups == Some(true) {
            group.user_group_ids.clear();
        }
        // AuthToken rotation: SET / ROTATE store the new token, DELETE clears
        // it. Default strategy is SET when AuthToken is supplied without one.
        match new_auth_token_strategy.as_deref() {
            Some("DELETE") => {
                group.auth_token = None;
                group.auth_token_enabled = false;
            }
            Some("SET") | Some("ROTATE") => {
                if let Some(token) = new_auth_token {
                    group.auth_token = Some(token);
                    group.auth_token_enabled = true;
                }
            }
            Some(other) => {
                return Err(AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidParameterValue",
                    format!(
                        "Invalid value for AuthTokenUpdateStrategy: '{other}'. Valid values: SET, ROTATE, DELETE."
                    ),
                ));
            }
            None => {
                if let Some(token) = new_auth_token {
                    group.auth_token = Some(token);
                    group.auth_token_enabled = true;
                }
            }
        }

        // Associate/disassociate user groups
        for ug_id in &user_group_ids_to_add {
            if let Some(ug) = state.user_groups.get_mut(ug_id) {
                if !ug.replication_groups.contains(&replication_group_id) {
                    ug.replication_groups.push(replication_group_id.clone());
                }
            }
        }
        for ug_id in &user_group_ids_to_remove {
            if let Some(ug) = state.user_groups.get_mut(ug_id) {
                ug.replication_groups
                    .retain(|id| id != &replication_group_id);
            }
        }

        let group = state.replication_groups[&replication_group_id].clone();
        let region = state.region.clone();
        let xml = replication_group_xml(&group, &region);

        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "ModifyReplicationGroup",
                ELASTICACHE_NS,
                &format!("<ReplicationGroup>{xml}</ReplicationGroup>"),
                &request.request_id,
            ),
        ))
    }

    fn modify_global_replication_group(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let global_replication_group_id =
            required_query_param(request, "GlobalReplicationGroupId")?;
        let _apply_immediately = parse_required_bool(request, "ApplyImmediately")?;
        let new_description = optional_query_param(request, "GlobalReplicationGroupDescription");
        let new_cache_node_type = optional_query_param(request, "CacheNodeType");
        let new_engine = optional_query_param(request, "Engine");
        let new_engine_version = optional_query_param(request, "EngineVersion");
        let new_automatic_failover = parse_optional_bool(
            optional_query_param(request, "AutomaticFailoverEnabled").as_deref(),
        )?;

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request.account_id);
        let primary_replication_group_id = state
            .global_replication_groups
            .get(&global_replication_group_id)
            .and_then(primary_global_member)
            .map(|member| member.replication_group_id.clone())
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::NOT_FOUND,
                    "GlobalReplicationGroupNotFoundFault",
                    format!("GlobalReplicationGroup {global_replication_group_id} not found."),
                )
            })?;

        if let Some(ref engine) = new_engine {
            validate_serverless_engine(engine)?;
            let current_engine =
                &state.global_replication_groups[&global_replication_group_id].engine;
            if engine != current_engine {
                return Err(AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidParameterValue",
                    format!(
                        "Engine changes are not supported for GlobalReplicationGroup {global_replication_group_id}."
                    ),
                ));
            }
        }

        if let Some(primary_group) = state
            .replication_groups
            .get_mut(&primary_replication_group_id)
        {
            if let Some(cache_node_type) = new_cache_node_type.clone() {
                primary_group.cache_node_type = cache_node_type;
            }
            if let Some(engine_version) = new_engine_version.clone() {
                primary_group.engine_version = engine_version;
            }
            if let Some(automatic_failover) = new_automatic_failover {
                primary_group.automatic_failover_enabled = automatic_failover;
            }
        }

        let primary_group = state.replication_groups[&primary_replication_group_id].clone();
        let group = state
            .global_replication_groups
            .get_mut(&global_replication_group_id)
            .expect("global replication group exists");
        if let Some(description) = new_description {
            group.global_replication_group_description = description;
        }
        group.cache_node_type = primary_group.cache_node_type.clone();
        group.engine = primary_group.engine.clone();
        group.engine_version = primary_group.engine_version.clone();
        if let Some(member) = group
            .members
            .iter_mut()
            .find(|member| member.role == "primary")
        {
            member.automatic_failover = primary_group.automatic_failover_enabled;
        }

        let xml = global_replication_group_xml(group, true);
        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "ModifyGlobalReplicationGroup",
                ELASTICACHE_NS,
                &format!("<GlobalReplicationGroup>{xml}</GlobalReplicationGroup>"),
                &request.request_id,
            ),
        ))
    }

    fn increase_replica_count(&self, request: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let replication_group_id = required_query_param(request, "ReplicationGroupId")?;
        let apply_str = required_query_param(request, "ApplyImmediately")?;
        let _apply_immediately = parse_optional_bool(Some(&apply_str))?.ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidParameterValue",
                format!(
                    "Invalid boolean value for ApplyImmediately: '{}'",
                    apply_str
                ),
            )
        })?;

        let new_replica_count = optional_query_param(request, "NewReplicaCount")
            .map(|v| {
                v.parse::<i32>().map_err(|_| {
                    AwsServiceError::aws_error(
                        StatusCode::BAD_REQUEST,
                        "InvalidParameterValue",
                        format!("Invalid value for NewReplicaCount: '{v}'"),
                    )
                })
            })
            .transpose()?
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "MissingParameter",
                    "The request must contain the parameter NewReplicaCount.".to_string(),
                )
            })?;

        if new_replica_count < 1 {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidParameterValue",
                format!("NewReplicaCount must be a positive integer, got {new_replica_count}"),
            ));
        }

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request.account_id);

        let group = state
            .replication_groups
            .get_mut(&replication_group_id)
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::NOT_FOUND,
                    "ReplicationGroupNotFoundFault",
                    format!("ReplicationGroup {replication_group_id} not found."),
                )
            })?;

        // new_replica_count is number of replicas (excluding primary), so total clusters = replicas + 1
        let new_total = new_replica_count.checked_add(1).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidParameterValue",
                format!("NewReplicaCount value {new_replica_count} is too large"),
            )
        })?;
        if new_total <= group.num_cache_clusters {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidParameterValue",
                format!(
                    "NewReplicaCount ({new_replica_count}) must result in more clusters than current count ({}).",
                    group.num_cache_clusters
                ),
            ));
        }

        group.num_cache_clusters = new_total;
        group.member_clusters = (1..=new_total)
            .map(|i| format!("{replication_group_id}-{i:03}"))
            .collect();

        let group = group.clone();
        let region = state.region.clone();
        let xml = replication_group_xml(&group, &region);

        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "IncreaseReplicaCount",
                ELASTICACHE_NS,
                &format!("<ReplicationGroup>{xml}</ReplicationGroup>"),
                &request.request_id,
            ),
        ))
    }

    fn decrease_replica_count(&self, request: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let replication_group_id = required_query_param(request, "ReplicationGroupId")?;
        let apply_str = required_query_param(request, "ApplyImmediately")?;
        let _apply_immediately = parse_optional_bool(Some(&apply_str))?.ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidParameterValue",
                format!(
                    "Invalid boolean value for ApplyImmediately: '{}'",
                    apply_str
                ),
            )
        })?;

        let new_replica_count = optional_query_param(request, "NewReplicaCount")
            .map(|v| {
                v.parse::<i32>().map_err(|_| {
                    AwsServiceError::aws_error(
                        StatusCode::BAD_REQUEST,
                        "InvalidParameterValue",
                        format!("Invalid value for NewReplicaCount: '{v}'"),
                    )
                })
            })
            .transpose()?
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "MissingParameter",
                    "The request must contain the parameter NewReplicaCount.".to_string(),
                )
            })?;

        if new_replica_count < 0 {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidParameterValue",
                format!("NewReplicaCount must be non-negative, got {new_replica_count}"),
            ));
        }

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request.account_id);

        let group = state
            .replication_groups
            .get_mut(&replication_group_id)
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::NOT_FOUND,
                    "ReplicationGroupNotFoundFault",
                    format!("ReplicationGroup {replication_group_id} not found."),
                )
            })?;

        // new_replica_count is number of replicas (excluding primary), so total clusters = replicas + 1
        let new_total = new_replica_count.checked_add(1).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidParameterValue",
                format!("NewReplicaCount value {new_replica_count} is too large"),
            )
        })?;
        if new_total >= group.num_cache_clusters {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidParameterValue",
                format!(
                    "NewReplicaCount ({new_replica_count}) must result in fewer clusters than current count ({}).",
                    group.num_cache_clusters
                ),
            ));
        }

        group.num_cache_clusters = new_total;
        group.member_clusters = (1..=new_total)
            .map(|i| format!("{replication_group_id}-{i:03}"))
            .collect();

        let group = group.clone();
        let region = state.region.clone();
        let xml = replication_group_xml(&group, &region);

        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "DecreaseReplicaCount",
                ELASTICACHE_NS,
                &format!("<ReplicationGroup>{xml}</ReplicationGroup>"),
                &request.request_id,
            ),
        ))
    }

    fn test_failover(&self, request: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let replication_group_id = required_query_param(request, "ReplicationGroupId")?;
        let node_group_id = required_query_param(request, "NodeGroupId")?;

        let accounts = self.state.read();
        let empty = ElastiCacheState::new(&request.account_id, &request.region);
        let state = accounts.get(&request.account_id).unwrap_or(&empty);

        let group = state
            .replication_groups
            .get(&replication_group_id)
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::NOT_FOUND,
                    "ReplicationGroupNotFoundFault",
                    format!("ReplicationGroup {replication_group_id} not found."),
                )
            })?;

        // Our replication groups always have a single node group with ID "0001"
        if node_group_id != "0001" {
            return Err(AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "NodeGroupNotFoundFault",
                format!("NodeGroup {node_group_id} not found in ReplicationGroup {replication_group_id}."),
            ));
        }

        let region = state.region.clone();
        let xml = replication_group_xml(group, &region);

        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "TestFailover",
                ELASTICACHE_NS,
                &format!("<ReplicationGroup>{xml}</ReplicationGroup>"),
                &request.request_id,
            ),
        ))
    }

    fn disassociate_global_replication_group(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let global_replication_group_id =
            required_query_param(request, "GlobalReplicationGroupId")?;
        let replication_group_id = required_query_param(request, "ReplicationGroupId")?;
        let replication_group_region = required_query_param(request, "ReplicationGroupRegion")?;

        let accounts = self.state.read();
        let empty = ElastiCacheState::new(&request.account_id, &request.region);
        let state = accounts.get(&request.account_id).unwrap_or(&empty);
        let group = state
            .global_replication_groups
            .get(&global_replication_group_id)
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::NOT_FOUND,
                    "GlobalReplicationGroupNotFoundFault",
                    format!("GlobalReplicationGroup {global_replication_group_id} not found."),
                )
            })?;

        let primary_member = primary_global_member(group).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidGlobalReplicationGroupState",
                format!(
                    "GlobalReplicationGroup {global_replication_group_id} does not have a primary member."
                ),
            )
        })?;
        if primary_member.replication_group_id != replication_group_id
            || primary_member.replication_group_region != replication_group_region
        {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidParameterValue",
                format!(
                    "ReplicationGroup {replication_group_id} in region {replication_group_region} is not associated with GlobalReplicationGroup {global_replication_group_id}."
                ),
            ));
        }

        let xml = global_replication_group_xml(group, true);
        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "DisassociateGlobalReplicationGroup",
                ELASTICACHE_NS,
                &format!("<GlobalReplicationGroup>{xml}</GlobalReplicationGroup>"),
                &request.request_id,
            ),
        ))
    }

    fn failover_global_replication_group(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let global_replication_group_id =
            required_query_param(request, "GlobalReplicationGroupId")?;
        let primary_region = required_query_param(request, "PrimaryRegion")?;
        let primary_replication_group_id =
            required_query_param(request, "PrimaryReplicationGroupId")?;

        let accounts = self.state.read();
        let empty = ElastiCacheState::new(&request.account_id, &request.region);
        let state = accounts.get(&request.account_id).unwrap_or(&empty);
        let group = state
            .global_replication_groups
            .get(&global_replication_group_id)
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::NOT_FOUND,
                    "GlobalReplicationGroupNotFoundFault",
                    format!("GlobalReplicationGroup {global_replication_group_id} not found."),
                )
            })?;

        let primary_member = primary_global_member(group).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidGlobalReplicationGroupState",
                format!(
                    "GlobalReplicationGroup {global_replication_group_id} does not have a primary member."
                ),
            )
        })?;
        if primary_member.replication_group_id != primary_replication_group_id
            || primary_member.replication_group_region != primary_region
        {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidParameterValue",
                format!(
                    "PrimaryReplicationGroupId and PrimaryRegion do not match the current primary for GlobalReplicationGroup {global_replication_group_id}."
                ),
            ));
        }

        let xml = global_replication_group_xml(group, true);
        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "FailoverGlobalReplicationGroup",
                ELASTICACHE_NS,
                &format!("<GlobalReplicationGroup>{xml}</GlobalReplicationGroup>"),
                &request.request_id,
            ),
        ))
    }

    fn create_user(&self, request: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let user_id = required_query_param(request, "UserId")?;
        let user_name = required_query_param(request, "UserName")?;
        let engine = required_query_param(request, "Engine")?;
        let access_string = required_query_param(request, "AccessString")?;

        validate_engine(&engine)?;

        let no_password_required =
            parse_optional_bool(optional_query_param(request, "NoPasswordRequired").as_deref())?
                .unwrap_or(false);
        let passwords = parse_member_list(&request.query_params, "Passwords", "member");
        let auth_mode_type = optional_query_param(request, "AuthenticationMode.Type");

        let (authentication_type, password_count) = if no_password_required {
            if !passwords.is_empty() {
                return Err(AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidParameterCombination",
                    "Passwords cannot be provided when NoPasswordRequired is true.".to_string(),
                ));
            }
            ("no-password".to_string(), 0)
        } else if let Some(ref mode) = auth_mode_type {
            let mode_passwords = parse_member_list(
                &request.query_params,
                "AuthenticationMode.Passwords",
                "member",
            );
            match mode.as_str() {
                "password" => {
                    if mode_passwords.is_empty() {
                        return Err(AwsServiceError::aws_error(
                            StatusCode::BAD_REQUEST,
                            "InvalidParameterValue",
                            "At least one password is required when AuthenticationMode.Type is password.".to_string(),
                        ));
                    }
                    ("password".to_string(), mode_passwords.len() as i32)
                }
                "no-password-required" | "iam" => {
                    if !mode_passwords.is_empty() {
                        return Err(AwsServiceError::aws_error(
                            StatusCode::BAD_REQUEST,
                            "InvalidParameterValue",
                            format!("Passwords cannot be provided when AuthenticationMode.Type is {mode}."),
                        ));
                    }
                    (mode.clone(), 0)
                }
                _ => {
                    return Err(AwsServiceError::aws_error(
                        StatusCode::BAD_REQUEST,
                        "InvalidParameterValue",
                        format!("Invalid value for AuthenticationMode.Type: {mode}. Supported values: password, iam, no-password-required"),
                    ));
                }
            }
        } else if !passwords.is_empty() {
            ("password".to_string(), passwords.len() as i32)
        } else {
            ("no-password".to_string(), 0)
        };

        let minimum_engine_version = if engine == ENGINE_VALKEY {
            "8.0".to_string()
        } else {
            "6.0".to_string()
        };

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request.account_id);

        if state.users.contains_key(&user_id) {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "UserAlreadyExistsFault",
                format!("User {user_id} already exists."),
            ));
        }

        let arn = format!(
            "arn:aws:elasticache:{}:{}:user:{}",
            state.region, state.account_id, user_id
        );

        let user = ElastiCacheUser {
            user_id: user_id.clone(),
            user_name,
            engine,
            access_string,
            status: "active".to_string(),
            authentication_type,
            password_count,
            arn,
            minimum_engine_version,
            user_group_ids: Vec::new(),
        };

        let xml = user_xml(&user);
        state.register_arn(&user.arn);
        state.users.insert(user_id, user);

        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml("CreateUser", ELASTICACHE_NS, &xml, &request.request_id),
        ))
    }

    fn describe_users(&self, request: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let user_id = optional_query_param(request, "UserId");
        let max_records = optional_usize_param(request, "MaxRecords")?;
        let marker = optional_query_param(request, "Marker");

        let accounts = self.state.read();
        let empty = ElastiCacheState::new(&request.account_id, &request.region);
        let state = accounts.get(&request.account_id).unwrap_or(&empty);

        let users: Vec<&ElastiCacheUser> = if let Some(ref id) = user_id {
            match state.users.get(id) {
                Some(u) => vec![u],
                None => {
                    return Err(AwsServiceError::aws_error(
                        StatusCode::NOT_FOUND,
                        "UserNotFoundFault",
                        format!("User {id} not found."),
                    ));
                }
            }
        } else {
            let mut users: Vec<&ElastiCacheUser> = state.users.values().collect();
            users.sort_by(|a, b| a.user_id.cmp(&b.user_id));
            users
        };

        let (page, next_marker) = paginate(&users, marker.as_deref(), max_records);

        let members_xml: String = page
            .iter()
            .map(|u| format!("<member>{}</member>", user_xml(u)))
            .collect();
        let marker_xml = next_marker
            .map(|m| format!("<Marker>{}</Marker>", xml_escape(&m)))
            .unwrap_or_default();

        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "DescribeUsers",
                ELASTICACHE_NS,
                &format!("<Users>{members_xml}</Users>{marker_xml}"),
                &request.request_id,
            ),
        ))
    }

    fn delete_user(&self, request: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let user_id = required_query_param(request, "UserId")?;

        if user_id == "default" {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidParameterValue",
                "Cannot delete the default user.".to_string(),
            ));
        }

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request.account_id);

        let user = state.users.remove(&user_id).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "UserNotFoundFault",
                format!("User {user_id} not found."),
            )
        })?;

        state.tags.remove(&user.arn);

        // Remove user from any user groups
        for group in state.user_groups.values_mut() {
            group.user_ids.retain(|id| id != &user_id);
        }

        let mut deleted_user = user;
        deleted_user.status = "deleting".to_string();
        let xml = user_xml(&deleted_user);

        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml("DeleteUser", ELASTICACHE_NS, &xml, &request.request_id),
        ))
    }

    fn create_user_group(&self, request: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let user_group_id = required_query_param(request, "UserGroupId")?;
        let engine = required_query_param(request, "Engine")?;

        validate_engine(&engine)?;

        let user_ids = parse_member_list(&request.query_params, "UserIds", "member");

        let minimum_engine_version = if engine == ENGINE_VALKEY {
            "8.0".to_string()
        } else {
            "6.0".to_string()
        };

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request.account_id);

        if state.user_groups.contains_key(&user_group_id) {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "UserGroupAlreadyExistsFault",
                format!("User Group {user_group_id} already exists."),
            ));
        }

        // Validate all referenced users exist and have a matching engine
        for uid in &user_ids {
            match state.users.get(uid) {
                None => {
                    return Err(AwsServiceError::aws_error(
                        StatusCode::NOT_FOUND,
                        "UserNotFoundFault",
                        format!("User {uid} not found."),
                    ));
                }
                Some(user) if user.engine != engine => {
                    return Err(AwsServiceError::aws_error(
                        StatusCode::BAD_REQUEST,
                        "InvalidParameterValue",
                        format!(
                            "User {uid} has engine {} which does not match the user group engine {engine}.",
                            user.engine
                        ),
                    ));
                }
                _ => {}
            }
        }

        let arn = format!(
            "arn:aws:elasticache:{}:{}:usergroup:{}",
            state.region, state.account_id, user_group_id
        );

        let group = ElastiCacheUserGroup {
            user_group_id: user_group_id.clone(),
            engine,
            status: "active".to_string(),
            user_ids: user_ids.clone(),
            arn,
            minimum_engine_version,
            pending_changes: None,
            replication_groups: Vec::new(),
        };

        // Update user_group_ids on referenced users
        for uid in &user_ids {
            if let Some(user) = state.users.get_mut(uid) {
                user.user_group_ids.push(user_group_id.clone());
            }
        }

        let xml = user_group_xml(&group);
        state.register_arn(&group.arn);
        state.user_groups.insert(user_group_id, group);

        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml("CreateUserGroup", ELASTICACHE_NS, &xml, &request.request_id),
        ))
    }

    fn describe_user_groups(&self, request: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let user_group_id = optional_query_param(request, "UserGroupId");
        let max_records = optional_usize_param(request, "MaxRecords")?;
        let marker = optional_query_param(request, "Marker");

        let accounts = self.state.read();
        let empty = ElastiCacheState::new(&request.account_id, &request.region);
        let state = accounts.get(&request.account_id).unwrap_or(&empty);

        let groups: Vec<&ElastiCacheUserGroup> = if let Some(ref id) = user_group_id {
            match state.user_groups.get(id) {
                Some(g) => vec![g],
                None => {
                    return Err(AwsServiceError::aws_error(
                        StatusCode::NOT_FOUND,
                        "UserGroupNotFoundFault",
                        format!("User Group {id} not found."),
                    ));
                }
            }
        } else {
            let mut groups: Vec<&ElastiCacheUserGroup> = state.user_groups.values().collect();
            groups.sort_by(|a, b| a.user_group_id.cmp(&b.user_group_id));
            groups
        };

        let (page, next_marker) = paginate(&groups, marker.as_deref(), max_records);

        let members_xml: String = page
            .iter()
            .map(|g| format!("<member>{}</member>", user_group_xml(g)))
            .collect();
        let marker_xml = next_marker
            .map(|m| format!("<Marker>{}</Marker>", xml_escape(&m)))
            .unwrap_or_default();

        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "DescribeUserGroups",
                ELASTICACHE_NS,
                &format!("<UserGroups>{members_xml}</UserGroups>{marker_xml}"),
                &request.request_id,
            ),
        ))
    }

    fn delete_user_group(&self, request: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let user_group_id = required_query_param(request, "UserGroupId")?;

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request.account_id);

        let group = state.user_groups.remove(&user_group_id).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "UserGroupNotFoundFault",
                format!("User Group {user_group_id} not found."),
            )
        })?;

        state.tags.remove(&group.arn);

        // Remove this group from users' user_group_ids
        for uid in &group.user_ids {
            if let Some(user) = state.users.get_mut(uid) {
                user.user_group_ids.retain(|gid| gid != &user_group_id);
            }
        }

        let mut deleted_group = group;
        deleted_group.status = "deleting".to_string();
        let xml = user_group_xml(&deleted_group);

        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml("DeleteUserGroup", ELASTICACHE_NS, &xml, &request.request_id),
        ))
    }

    fn add_tags_to_resource(&self, request: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let resource_name = required_query_param(request, "ResourceName")?;
        let tags = parse_tags(request)?;

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request.account_id);
        let tag_list = state.tags.get_mut(&resource_name).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "CacheClusterNotFound",
                format!("The resource {resource_name} could not be found."),
            )
        })?;

        merge_tags(tag_list, &tags);

        let tag_xml: String = tag_list.iter().map(tag_xml).collect();

        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "AddTagsToResource",
                ELASTICACHE_NS,
                &format!("<TagList>{tag_xml}</TagList>"),
                &request.request_id,
            ),
        ))
    }

    fn list_tags_for_resource(&self, request: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let resource_name = required_query_param(request, "ResourceName")?;

        let accounts = self.state.read();
        let empty = ElastiCacheState::new(&request.account_id, &request.region);
        let state = accounts.get(&request.account_id).unwrap_or(&empty);
        let tag_list = state.tags.get(&resource_name).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "CacheClusterNotFound",
                format!("The resource {resource_name} could not be found."),
            )
        })?;

        let tag_xml: String = tag_list.iter().map(tag_xml).collect();

        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "ListTagsForResource",
                ELASTICACHE_NS,
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

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request.account_id);
        let tag_list = state.tags.get_mut(&resource_name).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "CacheClusterNotFound",
                format!("The resource {resource_name} could not be found."),
            )
        })?;

        tag_list.retain(|(key, _)| !tag_keys.contains(key));

        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "RemoveTagsFromResource",
                ELASTICACHE_NS,
                "",
                &request.request_id,
            ),
        ))
    }

    // ── Cache Security Groups ──

    fn create_cache_security_group(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let name = required_query_param(request, "CacheSecurityGroupName")?;
        let description = required_query_param(request, "Description")?;

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request.account_id);
        if state.security_groups.contains_key(&name) {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "CacheSecurityGroupAlreadyExists",
                format!("CacheSecurityGroup {name} already exists."),
            ));
        }
        let arn = format!(
            "arn:aws:elasticache:{}:{}:securitygroup:{}",
            request.region, request.account_id, name
        );
        let sg = crate::state::CacheSecurityGroup {
            cache_security_group_name: name.clone(),
            description,
            owner_id: request.account_id.clone(),
            arn: arn.clone(),
            ec2_security_groups: Vec::new(),
        };
        state.security_groups.insert(name.clone(), sg.clone());
        let xml = format!(
            "<CacheSecurityGroup>{}</CacheSecurityGroup>",
            cache_security_group_xml(&sg)
        );
        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "CreateCacheSecurityGroup",
                ELASTICACHE_NS,
                &xml,
                &request.request_id,
            ),
        ))
    }

    fn delete_cache_security_group(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let name = required_query_param(request, "CacheSecurityGroupName")?;
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request.account_id);
        state.security_groups.remove(&name).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "CacheSecurityGroupNotFound",
                format!("CacheSecurityGroup {name} not found."),
            )
        })?;
        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "DeleteCacheSecurityGroup",
                ELASTICACHE_NS,
                "",
                &request.request_id,
            ),
        ))
    }

    fn describe_cache_security_groups(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let name = optional_query_param(request, "CacheSecurityGroupName");
        let max_records = optional_usize_param(request, "MaxRecords")?;
        let marker = optional_query_param(request, "Marker");

        let accounts = self.state.read();
        let empty = ElastiCacheState::new(&request.account_id, &request.region);
        let state = accounts.get(&request.account_id).unwrap_or(&empty);
        let mut groups: Vec<&crate::state::CacheSecurityGroup> = state
            .security_groups
            .values()
            .filter(|g| {
                name.as_ref()
                    .is_none_or(|n| g.cache_security_group_name == *n)
            })
            .collect();
        groups.sort_by(|a, b| {
            a.cache_security_group_name
                .cmp(&b.cache_security_group_name)
        });
        if let Some(ref n) = name {
            if groups.is_empty() {
                return Err(AwsServiceError::aws_error(
                    StatusCode::NOT_FOUND,
                    "CacheSecurityGroupNotFound",
                    format!("CacheSecurityGroup {n} not found."),
                ));
            }
        }
        let (page, next_marker) = paginate(&groups, marker.as_deref(), max_records);
        let members: String = page
            .iter()
            .map(|g| {
                format!(
                    "<CacheSecurityGroup>{}</CacheSecurityGroup>",
                    cache_security_group_xml(g)
                )
            })
            .collect();
        let marker_xml = next_marker
            .map(|m| format!("<Marker>{}</Marker>", xml_escape(&m)))
            .unwrap_or_default();
        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "DescribeCacheSecurityGroups",
                ELASTICACHE_NS,
                &format!("<CacheSecurityGroups>{members}</CacheSecurityGroups>{marker_xml}"),
                &request.request_id,
            ),
        ))
    }

    fn authorize_cache_security_group_ingress(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let name = required_query_param(request, "CacheSecurityGroupName")?;
        let ec2_name = required_query_param(request, "EC2SecurityGroupName")?;
        let ec2_owner = required_query_param(request, "EC2SecurityGroupOwnerId")?;

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request.account_id);
        let sg = state.security_groups.get_mut(&name).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "CacheSecurityGroupNotFound",
                format!("CacheSecurityGroup {name} not found."),
            )
        })?;
        if sg.ec2_security_groups.iter().any(|e| {
            e.ec2_security_group_name == ec2_name && e.ec2_security_group_owner_id == ec2_owner
        }) {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "AuthorizationAlreadyExists",
                format!("Ingress for {ec2_name} already authorized."),
            ));
        }
        sg.ec2_security_groups
            .push(crate::state::Ec2SecurityGroupAuth {
                status: "authorizing".to_string(),
                ec2_security_group_name: ec2_name,
                ec2_security_group_owner_id: ec2_owner,
            });
        let xml = format!(
            "<CacheSecurityGroup>{}</CacheSecurityGroup>",
            cache_security_group_xml(sg)
        );
        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "AuthorizeCacheSecurityGroupIngress",
                ELASTICACHE_NS,
                &xml,
                &request.request_id,
            ),
        ))
    }

    fn revoke_cache_security_group_ingress(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let name = required_query_param(request, "CacheSecurityGroupName")?;
        let ec2_name = required_query_param(request, "EC2SecurityGroupName")?;
        let ec2_owner = required_query_param(request, "EC2SecurityGroupOwnerId")?;
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request.account_id);
        let sg = state.security_groups.get_mut(&name).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "CacheSecurityGroupNotFound",
                format!("CacheSecurityGroup {name} not found."),
            )
        })?;
        let before = sg.ec2_security_groups.len();
        sg.ec2_security_groups.retain(|e| {
            !(e.ec2_security_group_name == ec2_name && e.ec2_security_group_owner_id == ec2_owner)
        });
        if sg.ec2_security_groups.len() == before {
            return Err(AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "AuthorizationNotFound",
                format!("Ingress for {ec2_name} not found."),
            ));
        }
        let xml = format!(
            "<CacheSecurityGroup>{}</CacheSecurityGroup>",
            cache_security_group_xml(sg)
        );
        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "RevokeCacheSecurityGroupIngress",
                ELASTICACHE_NS,
                &xml,
                &request.request_id,
            ),
        ))
    }

    // ── Cache Parameter Groups (CRUD beyond Describe) ──

    fn create_cache_parameter_group(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let name = required_query_param(request, "CacheParameterGroupName")?;
        let family = required_query_param(request, "CacheParameterGroupFamily")?;
        let description = required_query_param(request, "Description")?;

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request.account_id);
        if state
            .parameter_groups
            .iter()
            .any(|g| g.cache_parameter_group_name == name)
        {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "CacheParameterGroupAlreadyExists",
                format!("CacheParameterGroup {name} already exists."),
            ));
        }
        let arn = format!(
            "arn:aws:elasticache:{}:{}:parametergroup:{}",
            request.region, request.account_id, name
        );
        let group = CacheParameterGroup {
            cache_parameter_group_name: name.clone(),
            cache_parameter_group_family: family,
            description,
            is_global: false,
            arn,
        };
        state.parameter_groups.push(group.clone());
        let xml = cache_parameter_group_xml(&group);
        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "CreateCacheParameterGroup",
                ELASTICACHE_NS,
                &xml,
                &request.request_id,
            ),
        ))
    }

    fn delete_cache_parameter_group(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let name = required_query_param(request, "CacheParameterGroupName")?;
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request.account_id);
        let before = state.parameter_groups.len();
        state
            .parameter_groups
            .retain(|g| g.cache_parameter_group_name != name);
        if state.parameter_groups.len() == before {
            return Err(AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "CacheParameterGroupNotFound",
                format!("CacheParameterGroup {name} not found."),
            ));
        }
        state.parameter_group_parameters.remove(&name);
        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "DeleteCacheParameterGroup",
                ELASTICACHE_NS,
                "",
                &request.request_id,
            ),
        ))
    }

    fn modify_cache_parameter_group(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let name = required_query_param(request, "CacheParameterGroupName")?;
        let updates = collect_indexed_pairs(
            request,
            "ParameterNameValues.member",
            "ParameterName",
            "ParameterValue",
        );
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request.account_id);
        if !state
            .parameter_groups
            .iter()
            .any(|g| g.cache_parameter_group_name == name)
        {
            return Err(AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "CacheParameterGroupNotFound",
                format!("CacheParameterGroup {name} not found."),
            ));
        }
        let params = state
            .parameter_group_parameters
            .entry(name.clone())
            .or_default();
        for (param_name, value) in updates {
            if let Some(existing) = params.iter_mut().find(|p| p.parameter_name == param_name) {
                existing.parameter_value = value;
                existing.source = "user".to_string();
            } else {
                params.push(crate::state::CacheParameter {
                    parameter_name: param_name,
                    parameter_value: value,
                    description: String::new(),
                    source: "user".to_string(),
                    data_type: "string".to_string(),
                    allowed_values: String::new(),
                    is_modifiable: true,
                    minimum_engine_version: String::new(),
                });
            }
        }
        let body = format!(
            "<CacheParameterGroupName>{}</CacheParameterGroupName>",
            xml_escape(&name)
        );
        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "ModifyCacheParameterGroup",
                ELASTICACHE_NS,
                &body,
                &request.request_id,
            ),
        ))
    }

    fn reset_cache_parameter_group(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let name = required_query_param(request, "CacheParameterGroupName")?;
        let reset_all =
            parse_optional_bool(optional_query_param(request, "ResetAllParameters").as_deref())?
                .unwrap_or(false);
        let to_reset = collect_member_field(request, "ParameterNameValues.member", "ParameterName");
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request.account_id);
        if !state
            .parameter_groups
            .iter()
            .any(|g| g.cache_parameter_group_name == name)
        {
            return Err(AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "CacheParameterGroupNotFound",
                format!("CacheParameterGroup {name} not found."),
            ));
        }
        if reset_all {
            state.parameter_group_parameters.remove(&name);
        } else if let Some(params) = state.parameter_group_parameters.get_mut(&name) {
            params.retain(|p| !to_reset.contains(&p.parameter_name));
        }
        let body = format!(
            "<CacheParameterGroupName>{}</CacheParameterGroupName>",
            xml_escape(&name)
        );
        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "ResetCacheParameterGroup",
                ELASTICACHE_NS,
                &body,
                &request.request_id,
            ),
        ))
    }

    fn describe_cache_parameters(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let name = required_query_param(request, "CacheParameterGroupName")?;
        let max_records = optional_usize_param(request, "MaxRecords")?;
        let marker = optional_query_param(request, "Marker");

        let accounts = self.state.read();
        let empty = ElastiCacheState::new(&request.account_id, &request.region);
        let state = accounts.get(&request.account_id).unwrap_or(&empty);
        if !state
            .parameter_groups
            .iter()
            .any(|g| g.cache_parameter_group_name == name)
        {
            return Err(AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "CacheParameterGroupNotFound",
                format!("CacheParameterGroup {name} not found."),
            ));
        }
        let params: Vec<&crate::state::CacheParameter> = state
            .parameter_group_parameters
            .get(&name)
            .map(|v| v.iter().collect())
            .unwrap_or_default();
        let (page, next_marker) = paginate(&params, marker.as_deref(), max_records);
        let members: String = page.iter().map(|p| cache_parameter_xml(p)).collect();
        let marker_xml = next_marker
            .map(|m| format!("<Marker>{}</Marker>", xml_escape(&m)))
            .unwrap_or_default();
        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "DescribeCacheParameters", ELASTICACHE_NS,
                &format!("<Parameters>{members}</Parameters><CacheNodeTypeSpecificParameters/>{marker_xml}"),
                &request.request_id,
            ),
        ))
    }

    // ── Cluster lifecycle extras ──

    fn modify_cache_cluster(&self, request: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let id = required_query_param(request, "CacheClusterId")?;
        let new_node_count = optional_query_param(request, "NumCacheNodes")
            .as_deref()
            .and_then(|v| v.parse::<i32>().ok());
        let new_node_type = optional_query_param(request, "CacheNodeType");

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request.account_id);
        let cluster = state.cache_clusters.get_mut(&id).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "CacheClusterNotFound",
                format!("CacheCluster {id} not found."),
            )
        })?;
        if let Some(n) = new_node_count {
            cluster.num_cache_nodes = n;
        }
        if let Some(t) = new_node_type {
            cluster.cache_node_type = t;
        }
        cluster.cache_cluster_status = "modifying".to_string();
        let xml = cache_cluster_xml(cluster, true);
        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "ModifyCacheCluster",
                ELASTICACHE_NS,
                &format!("<CacheCluster>{xml}</CacheCluster>"),
                &request.request_id,
            ),
        ))
    }

    async fn reboot_cache_cluster(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let id = required_query_param(request, "CacheClusterId")?;
        let xml = {
            let mut accounts = self.state.write();
            let state = accounts.get_or_create(&request.account_id);
            let cluster = state.cache_clusters.get_mut(&id).ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::NOT_FOUND,
                    "CacheClusterNotFound",
                    format!("CacheCluster {id} not found."),
                )
            })?;
            cluster.cache_cluster_status = "rebooting cache cluster nodes".to_string();
            cache_cluster_xml(cluster, true)
        };
        // Restart the underlying engine container so a real client
        // observes the reboot. Best-effort: if no runtime is wired up
        // (eg. tests, environments without docker) the API call still
        // reflects the rebooting state.
        if let Some(runtime) = &self.runtime {
            if let Err(error) = runtime.restart_container(&id).await {
                tracing::warn!(
                    cluster_id = %id,
                    %error,
                    "RebootCacheCluster: container restart failed, returning rebooting state anyway"
                );
            } else {
                let mut accounts = self.state.write();
                let state = accounts.get_or_create(&request.account_id);
                if let Some(cluster) = state.cache_clusters.get_mut(&id) {
                    cluster.cache_cluster_status = "available".to_string();
                }
            }
        }
        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "RebootCacheCluster",
                ELASTICACHE_NS,
                &format!("<CacheCluster>{xml}</CacheCluster>"),
                &request.request_id,
            ),
        ))
    }

    fn list_allowed_node_type_modifications(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        // Documented sample of upgradeable node types. Not exhaustive
        // but matches the shape SDKs decode.
        let scale_up = ["cache.t4g.medium", "cache.m6g.large", "cache.r6g.large"];
        let scale_down = ["cache.t4g.micro", "cache.t4g.small"];
        let mut body = String::from("<ScaleUpModifications>");
        for n in scale_up {
            body.push_str(&format!("<member>{}</member>", xml_escape(n)));
        }
        body.push_str("</ScaleUpModifications><ScaleDownModifications>");
        for n in scale_down {
            body.push_str(&format!("<member>{}</member>", xml_escape(n)));
        }
        body.push_str("</ScaleDownModifications>");
        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "ListAllowedNodeTypeModifications",
                ELASTICACHE_NS,
                &body,
                &request.request_id,
            ),
        ))
    }

    // ── Replication group + global replication group ──

    fn modify_replication_group_shard_configuration(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let id = required_query_param(request, "ReplicationGroupId")?;
        let _node_group_count = required_query_param(request, "NodeGroupCount")?;
        let _apply = required_query_param(request, "ApplyImmediately")?;
        let accounts = self.state.read();
        let empty = ElastiCacheState::new(&request.account_id, &request.region);
        let state = accounts.get(&request.account_id).unwrap_or(&empty);
        let group = state.replication_groups.get(&id).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "ReplicationGroupNotFoundFault",
                format!("ReplicationGroup {id} not found."),
            )
        })?;
        let region = state.region.clone();
        let xml = replication_group_xml(group, &region);
        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "ModifyReplicationGroupShardConfiguration",
                ELASTICACHE_NS,
                &format!("<ReplicationGroup>{xml}</ReplicationGroup>"),
                &request.request_id,
            ),
        ))
    }

    fn decrease_node_groups_in_global_replication_group(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        self.modify_global_node_groups(request, "DecreaseNodeGroupsInGlobalReplicationGroup")
    }

    fn increase_node_groups_in_global_replication_group(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        self.modify_global_node_groups(request, "IncreaseNodeGroupsInGlobalReplicationGroup")
    }

    fn rebalance_slots_in_global_replication_group(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        self.modify_global_node_groups(request, "RebalanceSlotsInGlobalReplicationGroup")
    }

    fn modify_global_node_groups(
        &self,
        request: &AwsRequest,
        action: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let id = required_query_param(request, "GlobalReplicationGroupId")?;
        let accounts = self.state.read();
        let empty = ElastiCacheState::new(&request.account_id, &request.region);
        let state = accounts.get(&request.account_id).unwrap_or(&empty);
        let group = state.global_replication_groups.get(&id).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "GlobalReplicationGroupNotFoundFault",
                format!("GlobalReplicationGroup {id} not found."),
            )
        })?;
        let xml = global_replication_group_xml(group, true);
        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                action,
                ELASTICACHE_NS,
                &format!("<GlobalReplicationGroup>{xml}</GlobalReplicationGroup>"),
                &request.request_id,
            ),
        ))
    }

    // ── Users / User groups (modify) ──

    fn modify_user(&self, request: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let id = required_query_param(request, "UserId")?;
        let access_string = optional_query_param(request, "AccessString");
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request.account_id);
        let user = state.users.get_mut(&id).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "UserNotFound",
                format!("User {id} not found."),
            )
        })?;
        if let Some(a) = access_string {
            user.access_string = a;
        }
        user.status = "modifying".to_string();
        let xml = user_xml(user);
        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml("ModifyUser", ELASTICACHE_NS, &xml, &request.request_id),
        ))
    }

    fn modify_user_group(&self, request: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let id = required_query_param(request, "UserGroupId")?;
        let to_add = collect_indexed_strings(request, "UserIdsToAdd.member");
        let to_remove = collect_indexed_strings(request, "UserIdsToRemove.member");
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request.account_id);
        let group = state.user_groups.get_mut(&id).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "UserGroupNotFoundFault",
                format!("UserGroup {id} not found."),
            )
        })?;
        for u in to_add {
            if !group.user_ids.contains(&u) {
                group.user_ids.push(u);
            }
        }
        group.user_ids.retain(|u| !to_remove.contains(u));
        group.status = "modifying".to_string();
        let xml = user_group_xml(group);
        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml("ModifyUserGroup", ELASTICACHE_NS, &xml, &request.request_id),
        ))
    }

    // ── Reserved cache nodes ──

    fn purchase_reserved_cache_nodes_offering(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let offering_id = required_query_param(request, "ReservedCacheNodesOfferingId")?;
        let id = optional_query_param(request, "ReservedCacheNodeId").unwrap_or_else(|| {
            format!(
                "ri-{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0)
            )
        });
        let count = optional_query_param(request, "CacheNodeCount")
            .as_deref()
            .and_then(|v| v.parse::<i32>().ok())
            .unwrap_or(1);

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request.account_id);
        let offering = state
            .reserved_cache_nodes_offerings
            .iter()
            .find(|o| o.reserved_cache_nodes_offering_id == offering_id)
            .cloned()
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::NOT_FOUND,
                    "ReservedCacheNodesOfferingNotFound",
                    format!("ReservedCacheNodesOffering {offering_id} not found."),
                )
            })?;
        let arn = format!(
            "arn:aws:elasticache:{}:{}:reserved-instance:{}",
            request.region, request.account_id, id
        );
        let node = ReservedCacheNode {
            reserved_cache_node_id: id.clone(),
            reserved_cache_nodes_offering_id: offering_id,
            cache_node_type: offering.cache_node_type,
            start_time: chrono::Utc::now().to_rfc3339(),
            duration: offering.duration,
            fixed_price: offering.fixed_price,
            usage_price: offering.usage_price,
            cache_node_count: count,
            product_description: offering.product_description,
            offering_type: offering.offering_type,
            state: "payment-pending".to_string(),
            recurring_charges: offering.recurring_charges,
            reservation_arn: arn,
        };
        state.reserved_cache_nodes.insert(id.clone(), node.clone());
        let xml = reserved_cache_node_xml(&node);
        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "PurchaseReservedCacheNodesOffering",
                ELASTICACHE_NS,
                &format!("<ReservedCacheNode>{xml}</ReservedCacheNode>"),
                &request.request_id,
            ),
        ))
    }

    // ── Events / Service updates / Update actions ──

    fn describe_events(&self, request: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let max_records = optional_usize_param(request, "MaxRecords")?;
        let marker = optional_query_param(request, "Marker");
        let accounts = self.state.read();
        let empty = ElastiCacheState::new(&request.account_id, &request.region);
        let state = accounts.get(&request.account_id).unwrap_or(&empty);
        let events: Vec<&crate::state::CacheEvent> = state.events.iter().collect();
        let (page, next_marker) = paginate(&events, marker.as_deref(), max_records);
        let members: String = page
            .iter()
            .map(|e| {
                format!(
                    "<Event><SourceIdentifier>{}</SourceIdentifier><SourceType>{}</SourceType><Message>{}</Message><Date>{}</Date></Event>",
                    xml_escape(&e.source_identifier),
                    xml_escape(&e.source_type),
                    xml_escape(&e.message),
                    xml_escape(&e.date),
                )
            })
            .collect();
        let marker_xml = next_marker
            .map(|m| format!("<Marker>{}</Marker>", xml_escape(&m)))
            .unwrap_or_default();
        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "DescribeEvents",
                ELASTICACHE_NS,
                &format!("<Events>{members}</Events>{marker_xml}"),
                &request.request_id,
            ),
        ))
    }

    fn describe_service_updates(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = "<ServiceUpdates/>";
        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "DescribeServiceUpdates",
                ELASTICACHE_NS,
                body,
                &request.request_id,
            ),
        ))
    }

    fn describe_update_actions(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = "<UpdateActions/>";
        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "DescribeUpdateActions",
                ELASTICACHE_NS,
                body,
                &request.request_id,
            ),
        ))
    }

    fn batch_apply_update_action(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        self.batch_update_action(request, "BatchApplyUpdateAction", "stopping")
    }

    fn batch_stop_update_action(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        self.batch_update_action(request, "BatchStopUpdateAction", "stopped")
    }

    fn batch_update_action(
        &self,
        request: &AwsRequest,
        action: &str,
        new_status: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let svc_update = required_query_param(request, "ServiceUpdateName")?;
        let cluster_ids = collect_indexed_strings(request, "CacheClusterIds.member");
        let group_ids = collect_indexed_strings(request, "ReplicationGroupIds.member");
        let processed: Vec<String> = cluster_ids
            .iter()
            .chain(group_ids.iter())
            .cloned()
            .collect();
        let processed_xml: String = processed
            .iter()
            .map(|id| {
                format!(
                    "<member><ServiceUpdateName>{}</ServiceUpdateName><ReplicationGroupId>{}</ReplicationGroupId><UpdateActionStatus>{}</UpdateActionStatus></member>",
                    xml_escape(&svc_update),
                    xml_escape(id),
                    xml_escape(new_status),
                )
            })
            .collect();
        let body = format!(
            "<ProcessedUpdateActions>{processed_xml}</ProcessedUpdateActions><UnprocessedUpdateActions/>"
        );
        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(action, ELASTICACHE_NS, &body, &request.request_id),
        ))
    }

    // ── Snapshots ──

    fn copy_snapshot(&self, request: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let source = required_query_param(request, "SourceSnapshotName")?;
        let target = required_query_param(request, "TargetSnapshotName")?;
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request.account_id);
        let mut snap = state.snapshots.get(&source).cloned().ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "SnapshotNotFoundFault",
                format!("Snapshot {source} not found."),
            )
        })?;
        if state.snapshots.contains_key(&target) {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "SnapshotAlreadyExistsFault",
                format!("Snapshot {target} already exists."),
            ));
        }
        snap.snapshot_name = target.clone();
        snap.snapshot_status = "creating".to_string();
        snap.snapshot_source = "manual".to_string();
        let xml = snapshot_xml(&snap);
        state.snapshots.insert(target, snap);
        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "CopySnapshot",
                ELASTICACHE_NS,
                &format!("<Snapshot>{xml}</Snapshot>"),
                &request.request_id,
            ),
        ))
    }

    fn copy_serverless_cache_snapshot(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let source = required_query_param(request, "SourceServerlessCacheSnapshotName")?;
        let target = required_query_param(request, "TargetServerlessCacheSnapshotName")?;
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request.account_id);
        if state.serverless_cache_snapshots.contains_key(&target) {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ServerlessCacheSnapshotAlreadyExistsFault",
                format!("ServerlessCacheSnapshot {target} already exists."),
            ));
        }
        let mut snap = state
            .serverless_cache_snapshots
            .get(&source)
            .cloned()
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::NOT_FOUND,
                    "ServerlessCacheSnapshotNotFoundFault",
                    format!("ServerlessCacheSnapshot {source} not found."),
                )
            })?;
        snap.serverless_cache_snapshot_name = target.clone();
        snap.status = "creating".to_string();
        let xml = serverless_cache_snapshot_xml(&snap);
        state.serverless_cache_snapshots.insert(target, snap);
        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "CopyServerlessCacheSnapshot",
                ELASTICACHE_NS,
                &format!("<ServerlessCacheSnapshot>{xml}</ServerlessCacheSnapshot>"),
                &request.request_id,
            ),
        ))
    }

    fn export_serverless_cache_snapshot(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let snap_name = required_query_param(request, "ServerlessCacheSnapshotName")?;
        let bucket = required_query_param(request, "S3BucketName")?;
        let accounts = self.state.read();
        let empty = ElastiCacheState::new(&request.account_id, &request.region);
        let state = accounts.get(&request.account_id).unwrap_or(&empty);
        let snap = state
            .serverless_cache_snapshots
            .get(&snap_name)
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::NOT_FOUND,
                    "ServerlessCacheSnapshotNotFoundFault",
                    format!("ServerlessCacheSnapshot {snap_name} not found."),
                )
            })?;
        let xml = serverless_cache_snapshot_xml(snap);
        let _ = bucket;
        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "ExportServerlessCacheSnapshot",
                ELASTICACHE_NS,
                &format!("<ServerlessCacheSnapshot>{xml}</ServerlessCacheSnapshot>"),
                &request.request_id,
            ),
        ))
    }

    // ── Migrations ──

    fn start_migration(&self, request: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        self.migration_op(request, "StartMigration", "queued")
    }

    fn complete_migration(&self, request: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let id = required_query_param(request, "ReplicationGroupId")?;
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request.account_id);
        let migration = state.migrations.get_mut(&id).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "ReplicationGroupNotUnderMigrationFault",
                format!("ReplicationGroup {id} is not currently being migrated."),
            )
        })?;
        migration.status = "complete".to_string();
        let group = state.replication_groups.get(&id).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "ReplicationGroupNotFoundFault",
                format!("ReplicationGroup {id} not found."),
            )
        })?;
        let region = state.region.clone();
        let xml = replication_group_xml(group, &region);
        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "CompleteMigration",
                ELASTICACHE_NS,
                &format!("<ReplicationGroup>{xml}</ReplicationGroup>"),
                &request.request_id,
            ),
        ))
    }

    fn test_migration(&self, request: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        self.migration_op(request, "TestMigration", "test-passed")
    }

    fn migration_op(
        &self,
        request: &AwsRequest,
        action: &str,
        status: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let id = required_query_param(request, "ReplicationGroupId")?;
        // AWS Query protocol nests indexed members under .{index}.{Field},
        // not .{Field}.{index}.
        let endpoint_addr =
            collect_member_field(request, "CustomerNodeEndpointList.member", "Address")
                .into_iter()
                .next()
                .unwrap_or_else(|| "127.0.0.1".to_string());
        let endpoint_port =
            collect_member_field(request, "CustomerNodeEndpointList.member", "Port")
                .into_iter()
                .next()
                .and_then(|v| v.parse::<i32>().ok())
                .unwrap_or(6379);

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request.account_id);
        let group = state.replication_groups.get(&id).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "ReplicationGroupNotFoundFault",
                format!("ReplicationGroup {id} not found."),
            )
        })?;
        let region = state.region.clone();
        let xml = replication_group_xml(group, &region);
        state.migrations.insert(
            id.clone(),
            crate::state::Migration {
                replication_group_id: id,
                customer_node_endpoint_address: endpoint_addr,
                customer_node_endpoint_port: endpoint_port,
                status: status.to_string(),
                started_at: chrono::Utc::now().to_rfc3339(),
            },
        );
        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                action,
                ELASTICACHE_NS,
                &format!("<ReplicationGroup>{xml}</ReplicationGroup>"),
                &request.request_id,
            ),
        ))
    }
}

// Helpers

#[path = "helpers.rs"]
mod helpers;
use helpers::*;

#[cfg(test)]
#[path = "service_tests.rs"]
mod tests;
