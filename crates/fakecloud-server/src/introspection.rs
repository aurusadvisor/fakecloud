//! Helpers that translate raw service state into the public introspection
//! response types from ``fakecloud-sdk``.
//!
//! These mappings exist so the ``GET /_fakecloud/...`` introspection endpoints
//! can hand back stable structs without leaking secrets (e.g. RDS master
//! passwords) or runtime-internal fields.

use fakecloud_sdk::types;

pub(crate) fn rds_instance_response(instance: &fakecloud_rds::DbInstance) -> types::RdsInstance {
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

pub(crate) fn ecr_repository_response(repo: &fakecloud_ecr::Repository) -> types::EcrRepository {
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
    repo: &fakecloud_ecr::Repository,
    image: &fakecloud_ecr::Image,
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
    rule: &fakecloud_ecr::PullThroughCacheRule,
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

pub(crate) fn ecs_task_response(task: &fakecloud_ecs::Task) -> types::EcsTask {
    types::EcsTask {
        task_arn: task.task_arn.clone(),
        task_id: task.task_id.clone(),
        cluster_arn: task.cluster_arn.clone(),
        cluster_name: task.cluster_name.clone(),
        task_definition_arn: task.task_definition_arn.clone(),
        family: task.family.clone(),
        revision: task.revision,
        last_status: task.last_status.clone(),
        desired_status: task.desired_status.clone(),
        launch_type: task.launch_type.clone(),
        created_at: task.created_at.to_rfc3339(),
        started_at: task.started_at.map(|t| t.to_rfc3339()),
        stopping_at: task.stopping_at.map(|t| t.to_rfc3339()),
        stopped_at: task.stopped_at.map(|t| t.to_rfc3339()),
        stop_code: task.stop_code.clone(),
        stopped_reason: task.stopped_reason.clone(),
        captured_log_bytes: task.captured_logs.len(),
        containers: task
            .containers
            .iter()
            .map(|c| types::EcsTaskContainer {
                name: c.name.clone(),
                image: c.image.clone(),
                last_status: c.last_status.clone(),
                exit_code: c.exit_code,
                runtime_id: c.runtime_id.clone(),
                essential: c.essential,
            })
            .collect(),
    }
}

pub(crate) fn ecs_lifecycle_event(
    event: &fakecloud_ecs::LifecycleEvent,
) -> types::EcsLifecycleEvent {
    types::EcsLifecycleEvent {
        at: event.at.to_rfc3339(),
        event_type: event.event_type.clone(),
        task_arn: event.task_arn.clone(),
        cluster_arn: event.cluster_arn.clone(),
        last_status: event.last_status.clone(),
        detail: event.detail.clone(),
    }
}

pub(crate) fn ecs_cluster_response(cluster: &fakecloud_ecs::Cluster) -> types::EcsCluster {
    types::EcsCluster {
        cluster_name: cluster.cluster_name.clone(),
        cluster_arn: cluster.cluster_arn.clone(),
        status: cluster.status.clone(),
        running_tasks_count: cluster.running_tasks_count,
        pending_tasks_count: cluster.pending_tasks_count,
        active_services_count: cluster.active_services_count,
        registered_container_instances_count: cluster.registered_container_instances_count,
        capacity_providers: cluster.capacity_providers.clone(),
        tags: cluster
            .tags
            .iter()
            .map(|t| types::EcsTag {
                key: t.key.clone(),
                value: t.value.clone(),
            })
            .collect(),
        created_at: cluster.created_at.to_rfc3339(),
    }
}

pub(crate) fn elasticache_cluster_response(
    cluster: &fakecloud_elasticache::CacheCluster,
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
    group: &fakecloud_elasticache::ReplicationGroup,
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
    cache: &fakecloud_elasticache::ServerlessCache,
) -> types::ElastiCacheServerlessCacheIntrospection {
    types::ElastiCacheServerlessCacheIntrospection {
        serverless_cache_name: cache.serverless_cache_name.clone(),
        status: cache.status.clone(),
        engine: cache.engine.clone(),
        engine_version: cache.full_engine_version.clone(),
        cache_node_type: None,
    }
}

pub(crate) fn elbv2_load_balancer_response(
    lb: &fakecloud_elbv2::LoadBalancer,
) -> types::Elbv2LoadBalancer {
    types::Elbv2LoadBalancer {
        arn: lb.arn.clone(),
        name: lb.name.clone(),
        dns_name: lb.dns_name.clone(),
        scheme: lb.scheme.clone(),
        vpc_id: lb.vpc_id.clone(),
        state_code: lb.state_code.clone(),
        state_reason: lb.state_reason.clone(),
        lb_type: lb.lb_type.clone(),
        ip_address_type: lb.ip_address_type.clone(),
        availability_zones: lb
            .availability_zones
            .iter()
            .map(|az| types::Elbv2AvailabilityZone {
                zone_name: az.zone_name.clone(),
                subnet_id: az.subnet_id.clone(),
            })
            .collect(),
        security_groups: lb.security_groups.clone(),
        created_time: lb.created_time.to_rfc3339(),
        tags: lb
            .tags
            .iter()
            .map(|t| types::Elbv2Tag {
                key: t.key.clone(),
                value: t.value.clone(),
            })
            .collect(),
        bound_port: lb.bound_port,
    }
}

pub(crate) fn elbv2_target_group_response(
    tg: &fakecloud_elbv2::TargetGroup,
) -> types::Elbv2TargetGroup {
    types::Elbv2TargetGroup {
        arn: tg.arn.clone(),
        name: tg.name.clone(),
        protocol: tg.protocol.clone(),
        port: tg.port,
        vpc_id: tg.vpc_id.clone(),
        target_type: tg.target_type.clone(),
        load_balancer_arns: tg.load_balancer_arns.clone(),
        targets: tg
            .targets
            .iter()
            .map(|t| types::Elbv2Target {
                id: t.id.clone(),
                port: t.port,
                availability_zone: t.availability_zone.clone(),
                health_state: t.health.state.clone(),
                health_reason: t.health.reason.clone(),
                health_description: t.health.description.clone(),
            })
            .collect(),
        health_check_protocol: tg.health_check_protocol.clone(),
        health_check_port: tg.health_check_port.clone(),
        health_check_path: tg.health_check_path.clone(),
        healthy_threshold_count: tg.healthy_threshold_count,
        unhealthy_threshold_count: tg.unhealthy_threshold_count,
        created_time: tg.created_time.to_rfc3339(),
        tags: tg
            .tags
            .iter()
            .map(|t| types::Elbv2Tag {
                key: t.key.clone(),
                value: t.value.clone(),
            })
            .collect(),
    }
}

pub(crate) fn elbv2_listener_response(l: &fakecloud_elbv2::Listener) -> types::Elbv2Listener {
    let default = l.default_actions.first();
    types::Elbv2Listener {
        arn: l.arn.clone(),
        load_balancer_arn: l.load_balancer_arn.clone(),
        port: l.port,
        protocol: l.protocol.clone(),
        ssl_policy: l.ssl_policy.clone(),
        certificate_arns: l
            .certificates
            .iter()
            .map(|c| c.certificate_arn.clone())
            .collect(),
        default_action_type: default.map(|a| a.action_type.clone()),
        default_target_group_arn: default.and_then(|a| a.target_group_arn.clone()),
    }
}

pub(crate) fn elbv2_rule_response(r: &fakecloud_elbv2::Rule) -> types::Elbv2Rule {
    types::Elbv2Rule {
        arn: r.arn.clone(),
        listener_arn: r.listener_arn.clone(),
        priority: r.priority.clone(),
        is_default: r.is_default,
        condition_fields: r.conditions.iter().map(|c| c.field.clone()).collect(),
        action_type: r.actions.first().map(|a| a.action_type.clone()),
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use fakecloud_rds::DbInstance;

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
            tags: vec![fakecloud_rds::RdsTag {
                key: "env".to_string(),
                value: "test".to_string(),
            }],
            read_replica_source_db_instance_identifier: None,
            read_replica_db_instance_identifiers: Vec::new(),
            vpc_security_group_ids: Vec::new(),
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
        };

        let response = rds_instance_response(&instance);

        assert_eq!(response.db_instance_identifier, "db-1");
        assert_eq!(response.container_id, "container-id");
        assert_eq!(response.host_port, 15432);
        assert_eq!(response.tags.len(), 1);
    }
}
