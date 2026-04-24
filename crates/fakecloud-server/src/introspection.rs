//! Helpers that translate raw service state into the public introspection
//! response types from ``fakecloud-sdk``.
//!
//! These mappings exist so the ``GET /_fakecloud/...`` introspection endpoints
//! can hand back stable structs without leaking secrets (e.g. RDS master
//! passwords) or runtime-internal fields.

use fakecloud_sdk::types;

pub(crate) fn rds_instance_response(
    instance: &fakecloud_rds::state::DbInstance,
) -> types::RdsInstance {
    types::RdsInstance {
        db_instance_identifier: instance.db_instance_identifier.clone(),
        db_instance_arn: instance.db_instance_arn.clone(),
        db_instance_class: instance.db_instance_class.clone(),
        engine: instance.engine.clone(),
        engine_version: instance.engine_version.clone(),
        db_instance_status: instance.db_instance_status.clone(),
        master_username: instance.master_username.clone(),
        db_name: instance.db_name.clone(),
        endpoint_address: instance.endpoint_address.clone(),
        port: instance.port,
        allocated_storage: instance.allocated_storage,
        publicly_accessible: instance.publicly_accessible,
        deletion_protection: instance.deletion_protection,
        created_at: instance.created_at.to_rfc3339(),
        dbi_resource_id: instance.dbi_resource_id.clone(),
        container_id: instance.container_id.clone(),
        host_port: instance.host_port,
        tags: instance
            .tags
            .iter()
            .map(|tag| types::RdsTag {
                key: tag.key.clone(),
                value: tag.value.clone(),
            })
            .collect(),
    }
}

pub(crate) fn ecr_repository_response(
    repo: &fakecloud_ecr::state::Repository,
) -> types::EcrRepository {
    let image_count = repo.images.len() as u64;
    let layer_count = repo.layers.len() as u64;
    types::EcrRepository {
        repository_name: repo.repository_name.clone(),
        repository_arn: repo.repository_arn.clone(),
        registry_id: repo.registry_id.clone(),
        repository_uri: repo.repository_uri.clone(),
        image_tag_mutability: repo.image_tag_mutability.clone(),
        scan_on_push: repo.image_scanning_configuration.scan_on_push,
        created_at: repo.created_at.to_rfc3339(),
        tags: repo
            .tags
            .iter()
            .map(|(k, v)| types::EcrTag {
                key: k.clone(),
                value: v.clone(),
            })
            .collect(),
        has_policy: repo.policy.is_some(),
        has_lifecycle_policy: repo.lifecycle_policy.is_some(),
        image_count,
        layer_count,
    }
}

pub(crate) fn ecr_image_response(
    repo: &fakecloud_ecr::state::Repository,
    image: &fakecloud_ecr::state::Image,
) -> types::EcrImage {
    let tags: Vec<String> = repo
        .image_tags
        .iter()
        .filter(|(_, d)| d.as_str() == image.image_digest)
        .map(|(t, _)| t.clone())
        .collect();
    types::EcrImage {
        repository_name: repo.repository_name.clone(),
        image_digest: image.image_digest.clone(),
        image_tags: tags,
        image_size_in_bytes: image.image_size_in_bytes,
        image_manifest_media_type: image.image_manifest_media_type.clone(),
        image_pushed_at: image.image_pushed_at.to_rfc3339(),
    }
}

pub(crate) fn ecr_pull_through_rule_response(
    rule: &fakecloud_ecr::state::PullThroughCacheRule,
) -> types::EcrPullThroughRule {
    types::EcrPullThroughRule {
        ecr_repository_prefix: rule.ecr_repository_prefix.clone(),
        upstream_registry_url: rule.upstream_registry_url.clone(),
        upstream_registry: rule.upstream_registry.clone(),
        credential_arn: rule.credential_arn.clone(),
        custom_role_arn: rule.custom_role_arn.clone(),
        created_at: rule.created_at.to_rfc3339(),
        updated_at: rule.updated_at.to_rfc3339(),
    }
}

pub(crate) fn elasticache_cluster_response(
    cluster: &fakecloud_elasticache::state::CacheCluster,
) -> types::ElastiCacheCluster {
    types::ElastiCacheCluster {
        cache_cluster_id: cluster.cache_cluster_id.clone(),
        cache_cluster_status: cluster.cache_cluster_status.clone(),
        engine: cluster.engine.clone(),
        engine_version: cluster.engine_version.clone(),
        cache_node_type: cluster.cache_node_type.clone(),
        num_cache_nodes: cluster.num_cache_nodes,
        replication_group_id: cluster.replication_group_id.clone(),
        port: Some(cluster.endpoint_port as i32),
        host_port: Some(cluster.host_port),
        container_id: Some(cluster.container_id.clone()),
    }
}

pub(crate) fn elasticache_replication_group_response(
    group: &fakecloud_elasticache::state::ReplicationGroup,
) -> types::ElastiCacheReplicationGroupIntrospection {
    types::ElastiCacheReplicationGroupIntrospection {
        replication_group_id: group.replication_group_id.clone(),
        status: group.status.clone(),
        description: group.description.clone(),
        member_clusters: group.member_clusters.clone(),
        automatic_failover: group.automatic_failover_enabled,
        multi_az: group.automatic_failover_enabled,
        engine: group.engine.clone(),
        engine_version: group.engine_version.clone(),
        cache_node_type: group.cache_node_type.clone(),
        num_cache_clusters: group.num_cache_clusters,
    }
}

pub(crate) fn elasticache_serverless_cache_response(
    cache: &fakecloud_elasticache::state::ServerlessCache,
) -> types::ElastiCacheServerlessCacheIntrospection {
    types::ElastiCacheServerlessCacheIntrospection {
        serverless_cache_name: cache.serverless_cache_name.clone(),
        status: cache.status.clone(),
        engine: cache.engine.clone(),
        engine_version: cache.full_engine_version.clone(),
        cache_node_type: None,
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use fakecloud_rds::state::DbInstance;

    use super::rds_instance_response;

    #[test]
    fn rds_instance_response_omits_password_but_keeps_runtime_metadata() {
        let created_at = Utc::now();
        let instance = DbInstance {
            db_instance_identifier: "db-1".to_string(),
            db_instance_arn: "arn:aws:rds:us-east-1:123456789012:db:db-1".to_string(),
            db_instance_class: "db.t3.micro".to_string(),
            engine: "postgres".to_string(),
            engine_version: "16.3".to_string(),
            db_instance_status: "available".to_string(),
            master_username: "admin".to_string(),
            db_name: Some("appdb".to_string()),
            endpoint_address: "127.0.0.1".to_string(),
            port: 15432,
            allocated_storage: 20,
            publicly_accessible: true,
            deletion_protection: false,
            created_at,
            dbi_resource_id: "db-test".to_string(),
            master_user_password: "secret123".to_string(),
            container_id: "container-id".to_string(),
            host_port: 15432,
            tags: vec![fakecloud_rds::state::RdsTag {
                key: "env".to_string(),
                value: "test".to_string(),
            }],
            read_replica_source_db_instance_identifier: None,
            read_replica_db_instance_identifiers: Vec::new(),
            vpc_security_group_ids: Vec::new(),
            db_parameter_group_name: None,
            backup_retention_period: 1,
            preferred_backup_window: "03:00-04:00".to_string(),
            latest_restorable_time: Some(created_at),
            option_group_name: None,
            multi_az: false,
            pending_modified_values: None,
        };

        let response = rds_instance_response(&instance);

        assert_eq!(response.db_instance_identifier, "db-1");
        assert_eq!(response.container_id, "container-id");
        assert_eq!(response.host_port, 15432);
        assert_eq!(response.tags.len(), 1);
    }
}
