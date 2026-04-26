//! RDS handlers added to close the conformance gap. Clusters, cluster
//! snapshots / parameter groups / endpoints, security groups, option
//! groups, event subscriptions, global clusters, integrations, blue/green
//! deployments, shard groups, custom engine versions, tenant databases,
//! proxies, export tasks, recommendations, certificates, accounts /
//! events / pending maintenance, and start/stop/reboot/failover ops.
//!
//! Persists into per-account state via the generic
//! `extras: HashMap<category, HashMap<id, Value>>` store on
//! `RdsState`. Returns valid Query-protocol XML responses with
//! stable IDs so SDK callers can chain operations.

use http::StatusCode;
use serde_json::{json, Value};
use std::collections::HashMap;

use fakecloud_aws::xml::xml_escape;
use fakecloud_core::service::{AwsRequest, AwsResponse, AwsServiceError};

use crate::service::{RdsService, RdsSourceType};

const NS: &str = "http://rds.amazonaws.com/doc/2014-10-31/";

fn rand_id() -> String {
    format!(
        "{:x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    )
}

fn xml_response(action: &str, inner: String, request_id: &str) -> AwsResponse {
    let body = format!(
        r#"<{action}Response xmlns="{NS}">
  <{action}Result>
{inner}
  </{action}Result>
  <ResponseMetadata>
    <RequestId>{rid}</RequestId>
  </ResponseMetadata>
</{action}Response>"#,
        action = action,
        NS = NS,
        inner = inner,
        rid = xml_escape(request_id),
    );
    AwsResponse::xml(StatusCode::OK, body)
}

fn xml_response_no_result(action: &str, request_id: &str) -> AwsResponse {
    let body = format!(
        r#"<{action}Response xmlns="{NS}">
  <ResponseMetadata>
    <RequestId>{rid}</RequestId>
  </ResponseMetadata>
</{action}Response>"#,
        action = action,
        NS = NS,
        rid = xml_escape(request_id),
    );
    AwsResponse::xml(StatusCode::OK, body)
}

fn members<F>(items: &[Value], render: F) -> String
where
    F: Fn(&Value) -> String,
{
    items
        .iter()
        .map(|v| format!("        <member>\n{}\n        </member>", render(v)))
        .collect::<Vec<_>>()
        .join("\n")
}

fn store<'a>(
    extras: &'a mut HashMap<String, HashMap<String, Value>>,
    category: &str,
) -> &'a mut HashMap<String, Value> {
    extras.entry(category.to_string()).or_default()
}

fn get_param(req: &AwsRequest, key: &str) -> Option<String> {
    if let Some(v) = req.query_params.get(key) {
        return Some(v.clone());
    }
    let body_params = fakecloud_core::protocol::parse_query_body(&req.body);
    body_params.get(key).cloned()
}

fn missing(name: &str) -> AwsServiceError {
    AwsServiceError::aws_error(
        StatusCode::BAD_REQUEST,
        "InvalidParameterValue",
        format!("{name} is required"),
    )
}

impl RdsService {
    pub(crate) fn handle_extra_action(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let action = req.action.clone();
        let aid = req.account_id.clone();
        let rid = req.request_id.clone();
        let region = "us-east-1"; // RDS uses us-east-1 by default in fakecloud

        macro_rules! write_state {
            () => {{
                let mut accounts = self.state_handle().write();
                accounts.get_or_create(&aid);
                accounts
            }};
        }

        match action.as_str() {
            // ── DB Clusters ──
            "CreateDBCluster" => {
                let id = get_param(req, "DBClusterIdentifier").ok_or_else(|| missing("DBClusterIdentifier"))?;
                let arn = format!("arn:aws:rds:{region}:{aid}:cluster:{id}");
                let entry = json!({
                    "DBClusterIdentifier": id, "DBClusterArn": arn,
                    "Status": "available", "Engine": get_param(req, "Engine").unwrap_or_else(|| "aurora-postgresql".to_string()),
                    "EngineVersion": get_param(req, "EngineVersion").unwrap_or_else(|| "15.3".to_string()),
                    "Endpoint": format!("{id}.cluster-xxx.{region}.rds.amazonaws.com"),
                    "ReaderEndpoint": format!("{id}.cluster-ro-xxx.{region}.rds.amazonaws.com"),
                    "Port": 5432, "MasterUsername": get_param(req, "MasterUsername").unwrap_or_else(|| "postgres".to_string()),
                });
                let mut accounts = write_state!();
                let state = accounts.get_or_create(&aid);
                store(&mut state.extras, "clusters").insert(id.clone(), entry);
                Ok(xml_response("CreateDBCluster", db_cluster_xml(&id, &arn), &rid))
            }
            "DeleteDBCluster" => {
                let id = get_param(req, "DBClusterIdentifier").ok_or_else(|| missing("DBClusterIdentifier"))?;
                let arn = format!("arn:aws:rds:{region}:{aid}:cluster:{id}");
                let mut accounts = write_state!();
                let state = accounts.get_or_create(&aid);
                if let Some(m) = state.extras.get_mut("clusters") { m.remove(&id); }
                Ok(xml_response("DeleteDBCluster", db_cluster_xml(&id, &arn), &rid))
            }
            "ModifyDBCluster" | "RebootDBCluster" | "StartDBCluster" | "StopDBCluster" | "FailoverDBCluster" | "BacktrackDBCluster" | "PromoteReadReplicaDBCluster" => {
                let id = get_param(req, "DBClusterIdentifier").unwrap_or_else(|| "default".to_string());
                let arn = format!("arn:aws:rds:{region}:{aid}:cluster:{id}");
                Ok(xml_response(action.as_str(), db_cluster_xml(&id, &arn), &rid))
            }
            "DescribeDBClusters" => {
                let accounts = self.state_handle().read();
                let items: Vec<Value> = accounts.get(&aid)
                    .and_then(|s| s.extras.get("clusters"))
                    .map(|m| m.values().cloned().collect()).unwrap_or_default();
                let inner = format!("    <DBClusters>\n{}\n    </DBClusters>",
                    members(&items, db_cluster_member_xml));
                Ok(xml_response("DescribeDBClusters", inner, &rid))
            }

            // ── DB Cluster snapshots ──
            "CreateDBClusterSnapshot" | "CopyDBClusterSnapshot" => {
                let id = get_param(req, "DBClusterSnapshotIdentifier").or_else(|| get_param(req, "TargetDBClusterSnapshotIdentifier"))
                    .ok_or_else(|| missing("DBClusterSnapshotIdentifier"))?;
                let arn = format!("arn:aws:rds:{region}:{aid}:cluster-snapshot:{id}");
                let cluster = get_param(req, "DBClusterIdentifier").unwrap_or_else(|| "default".to_string());
                let entry = json!({"DBClusterSnapshotIdentifier": id, "DBClusterSnapshotArn": arn, "DBClusterIdentifier": cluster, "Status": "available"});
                let mut accounts = write_state!();
                let state = accounts.get_or_create(&aid);
                store(&mut state.extras, "cluster_snapshots").insert(id.clone(), entry);
                Ok(xml_response(action.as_str(), cluster_snapshot_xml(&id, &arn, &cluster), &rid))
            }
            "DeleteDBClusterSnapshot" => {
                let id = get_param(req, "DBClusterSnapshotIdentifier").ok_or_else(|| missing("DBClusterSnapshotIdentifier"))?;
                let arn = format!("arn:aws:rds:{region}:{aid}:cluster-snapshot:{id}");
                let mut accounts = write_state!();
                let state = accounts.get_or_create(&aid);
                if let Some(m) = state.extras.get_mut("cluster_snapshots") { m.remove(&id); }
                Ok(xml_response("DeleteDBClusterSnapshot", cluster_snapshot_xml(&id, &arn, "default"), &rid))
            }
            "DescribeDBClusterSnapshots" => list_extras_xml(self, &aid, "cluster_snapshots", "DBClusterSnapshots", "DescribeDBClusterSnapshots", cluster_snapshot_member_xml, &rid),
            "DescribeDBClusterSnapshotAttributes" | "ModifyDBClusterSnapshotAttribute" => {
                let id = get_param(req, "DBClusterSnapshotIdentifier").unwrap_or_default();
                Ok(xml_response(action.as_str(), format!("    <DBClusterSnapshotAttributesResult>\n      <DBClusterSnapshotIdentifier>{}</DBClusterSnapshotIdentifier>\n      <DBClusterSnapshotAttributes/>\n    </DBClusterSnapshotAttributesResult>", xml_escape(&id)), &rid))
            }
            "DescribeDBClusterAutomatedBackups" => Ok(xml_response("DescribeDBClusterAutomatedBackups", "    <DBClusterAutomatedBackups/>".to_string(), &rid)),
            "DeleteDBClusterAutomatedBackup" => Ok(xml_response("DeleteDBClusterAutomatedBackup", "    <DBClusterAutomatedBackup/>".to_string(), &rid)),
            "DescribeDBClusterBacktracks" => Ok(xml_response("DescribeDBClusterBacktracks", "    <DBClusterBacktracks/>".to_string(), &rid)),

            // ── DB Cluster parameter groups ──
            "CreateDBClusterParameterGroup" | "CopyDBClusterParameterGroup" => {
                let name = get_param(req, "DBClusterParameterGroupName").or_else(|| get_param(req, "TargetDBClusterParameterGroupIdentifier"))
                    .ok_or_else(|| missing("DBClusterParameterGroupName"))?;
                let arn = format!("arn:aws:rds:{region}:{aid}:cluster-pg:{name}");
                let family = get_param(req, "DBParameterGroupFamily").unwrap_or_else(|| "aurora-postgresql15".to_string());
                let entry = json!({"DBClusterParameterGroupName": name, "DBClusterParameterGroupArn": arn, "DBParameterGroupFamily": family, "Description": get_param(req, "Description").unwrap_or_default()});
                let mut accounts = write_state!();
                let state = accounts.get_or_create(&aid);
                store(&mut state.extras, "cluster_param_groups").insert(name.clone(), entry);
                Ok(xml_response(action.as_str(), cluster_pg_xml(&name, &arn, &family), &rid))
            }
            "ModifyDBClusterParameterGroup" => {
                let name = get_param(req, "DBClusterParameterGroupName").ok_or_else(|| missing("DBClusterParameterGroupName"))?;
                Ok(xml_response("ModifyDBClusterParameterGroup", format!("    <DBClusterParameterGroupName>{}</DBClusterParameterGroupName>", xml_escape(&name)), &rid))
            }
            "ResetDBClusterParameterGroup" => {
                let name = get_param(req, "DBClusterParameterGroupName").ok_or_else(|| missing("DBClusterParameterGroupName"))?;
                Ok(xml_response("ResetDBClusterParameterGroup", format!("    <DBClusterParameterGroupName>{}</DBClusterParameterGroupName>", xml_escape(&name)), &rid))
            }
            "DeleteDBClusterParameterGroup" => {
                let name = get_param(req, "DBClusterParameterGroupName").ok_or_else(|| missing("DBClusterParameterGroupName"))?;
                let mut accounts = write_state!();
                let state = accounts.get_or_create(&aid);
                if let Some(m) = state.extras.get_mut("cluster_param_groups") { m.remove(&name); }
                xml_empty_action(&action, &rid)
            }
            "DescribeDBClusterParameterGroups" => list_extras_xml(self, &aid, "cluster_param_groups", "DBClusterParameterGroups", "DescribeDBClusterParameterGroups", cluster_pg_member_xml, &rid),
            "DescribeDBClusterParameters" => Ok(xml_response("DescribeDBClusterParameters", "    <Parameters/>".to_string(), &rid)),
            "DescribeEngineDefaultClusterParameters" => Ok(xml_response("DescribeEngineDefaultClusterParameters", "    <EngineDefaults>\n      <Parameters/>\n    </EngineDefaults>".to_string(), &rid)),

            // ── DB Cluster endpoints ──
            "CreateDBClusterEndpoint" => {
                let id = get_param(req, "DBClusterEndpointIdentifier").ok_or_else(|| missing("DBClusterEndpointIdentifier"))?;
                let cluster = get_param(req, "DBClusterIdentifier").unwrap_or_default();
                let kind = get_param(req, "EndpointType").unwrap_or_else(|| "READER".to_string());
                let entry = json!({"DBClusterEndpointIdentifier": id, "DBClusterIdentifier": cluster, "Endpoint": format!("{id}.cluster-custom.{region}.rds.amazonaws.com"), "EndpointType": kind, "Status": "available"});
                let mut accounts = write_state!();
                let state = accounts.get_or_create(&aid);
                store(&mut state.extras, "cluster_endpoints").insert(id.clone(), entry.clone());
                Ok(xml_response("CreateDBClusterEndpoint", cluster_endpoint_xml(&entry), &rid))
            }
            "ModifyDBClusterEndpoint" => Ok(xml_response("ModifyDBClusterEndpoint", "    <DBClusterEndpointIdentifier>x</DBClusterEndpointIdentifier>".to_string(), &rid)),
            "DeleteDBClusterEndpoint" => {
                let id = get_param(req, "DBClusterEndpointIdentifier").ok_or_else(|| missing("DBClusterEndpointIdentifier"))?;
                let mut accounts = write_state!();
                let state = accounts.get_or_create(&aid);
                if let Some(m) = state.extras.get_mut("cluster_endpoints") { m.remove(&id); }
                Ok(xml_response("DeleteDBClusterEndpoint", format!("    <DBClusterEndpointIdentifier>{}</DBClusterEndpointIdentifier>", xml_escape(&id)), &rid))
            }
            "DescribeDBClusterEndpoints" => list_extras_xml(self, &aid, "cluster_endpoints", "DBClusterEndpoints", "DescribeDBClusterEndpoints", cluster_endpoint_xml, &rid),

            // ── DB Proxies ──
            "CreateDBProxy" => {
                let name = get_param(req, "DBProxyName").ok_or_else(|| missing("DBProxyName"))?;
                let arn = format!("arn:aws:rds:{region}:{aid}:db-proxy:{name}");
                let entry = json!({"DBProxyName": name, "DBProxyArn": arn, "Status": "available", "EngineFamily": get_param(req, "EngineFamily").unwrap_or_else(|| "POSTGRESQL".to_string())});
                let mut accounts = write_state!();
                let state = accounts.get_or_create(&aid);
                store(&mut state.extras, "proxies").insert(name.clone(), entry.clone());
                Ok(xml_response("CreateDBProxy", proxy_xml(&entry), &rid))
            }
            "ModifyDBProxy" => Ok(xml_response("ModifyDBProxy", "    <DBProxy/>".to_string(), &rid)),
            "DeleteDBProxy" => {
                let name = get_param(req, "DBProxyName").ok_or_else(|| missing("DBProxyName"))?;
                let mut accounts = write_state!();
                let state = accounts.get_or_create(&aid);
                if let Some(m) = state.extras.get_mut("proxies") { m.remove(&name); }
                Ok(xml_response("DeleteDBProxy", "    <DBProxy/>".to_string(), &rid))
            }
            "DescribeDBProxies" => list_extras_xml(self, &aid, "proxies", "DBProxies", "DescribeDBProxies", proxy_xml, &rid),
            "CreateDBProxyEndpoint" => {
                let name = get_param(req, "DBProxyEndpointName").ok_or_else(|| missing("DBProxyEndpointName"))?;
                let entry = json!({"DBProxyEndpointName": name, "Status": "available"});
                let mut accounts = write_state!();
                let state = accounts.get_or_create(&aid);
                store(&mut state.extras, "proxy_endpoints").insert(name.clone(), entry);
                Ok(xml_response("CreateDBProxyEndpoint", format!("    <DBProxyEndpoint>\n      <DBProxyEndpointName>{}</DBProxyEndpointName>\n    </DBProxyEndpoint>", xml_escape(&name)), &rid))
            }
            "ModifyDBProxyEndpoint" => Ok(xml_response("ModifyDBProxyEndpoint", "    <DBProxyEndpoint/>".to_string(), &rid)),
            "DeleteDBProxyEndpoint" => {
                let name = get_param(req, "DBProxyEndpointName").ok_or_else(|| missing("DBProxyEndpointName"))?;
                let mut accounts = write_state!();
                let state = accounts.get_or_create(&aid);
                if let Some(m) = state.extras.get_mut("proxy_endpoints") { m.remove(&name); }
                Ok(xml_response("DeleteDBProxyEndpoint", "    <DBProxyEndpoint/>".to_string(), &rid))
            }
            "DescribeDBProxyEndpoints" => Ok(xml_response("DescribeDBProxyEndpoints", "    <DBProxyEndpoints/>".to_string(), &rid)),
            "DescribeDBProxyTargetGroups" => Ok(xml_response("DescribeDBProxyTargetGroups", "    <TargetGroups/>".to_string(), &rid)),
            "DescribeDBProxyTargets" => Ok(xml_response("DescribeDBProxyTargets", "    <Targets/>".to_string(), &rid)),
            "ModifyDBProxyTargetGroup" => Ok(xml_response("ModifyDBProxyTargetGroup", "    <DBProxyTargetGroup/>".to_string(), &rid)),
            "RegisterDBProxyTargets" => Ok(xml_response("RegisterDBProxyTargets", "    <DBProxyTargets/>".to_string(), &rid)),
            "DeregisterDBProxyTargets" => xml_empty_action(&action, &rid),

            // ── Security groups (legacy) ──
            "CreateDBSecurityGroup" | "AuthorizeDBSecurityGroupIngress" | "RevokeDBSecurityGroupIngress" => {
                let name = get_param(req, "DBSecurityGroupName").ok_or_else(|| missing("DBSecurityGroupName"))?;
                let entry = json!({"DBSecurityGroupName": name, "DBSecurityGroupDescription": get_param(req, "DBSecurityGroupDescription").unwrap_or_default(), "OwnerId": aid.clone()});
                let mut accounts = write_state!();
                let state = accounts.get_or_create(&aid);
                store(&mut state.extras, "security_groups").insert(name.clone(), entry.clone());
                Ok(xml_response(action.as_str(), security_group_xml(&entry), &rid))
            }
            "DeleteDBSecurityGroup" => {
                let name = get_param(req, "DBSecurityGroupName").ok_or_else(|| missing("DBSecurityGroupName"))?;
                let mut accounts = write_state!();
                let state = accounts.get_or_create(&aid);
                if let Some(m) = state.extras.get_mut("security_groups") { m.remove(&name); }
                xml_empty_action(&action, &rid)
            }
            "DescribeDBSecurityGroups" => list_extras_xml(self, &aid, "security_groups", "DBSecurityGroups", "DescribeDBSecurityGroups", security_group_xml, &rid),

            // ── Option groups ──
            "CreateOptionGroup" | "CopyOptionGroup" => {
                let name = get_param(req, "OptionGroupName").or_else(|| get_param(req, "TargetOptionGroupIdentifier"))
                    .ok_or_else(|| missing("OptionGroupName"))?;
                let arn = format!("arn:aws:rds:{region}:{aid}:og:{name}");
                let entry = json!({"OptionGroupName": name, "OptionGroupArn": arn, "EngineName": get_param(req, "EngineName").unwrap_or_else(|| "mysql".to_string()), "MajorEngineVersion": get_param(req, "MajorEngineVersion").unwrap_or_else(|| "8.0".to_string())});
                let mut accounts = write_state!();
                let state = accounts.get_or_create(&aid);
                store(&mut state.extras, "option_groups").insert(name.clone(), entry.clone());
                Ok(xml_response(action.as_str(), option_group_xml(&entry), &rid))
            }
            "ModifyOptionGroup" => {
                let name = get_param(req, "OptionGroupName").ok_or_else(|| missing("OptionGroupName"))?;
                Ok(xml_response("ModifyOptionGroup", format!("    <OptionGroup>\n      <OptionGroupName>{}</OptionGroupName>\n    </OptionGroup>", xml_escape(&name)), &rid))
            }
            "DeleteOptionGroup" => {
                let name = get_param(req, "OptionGroupName").ok_or_else(|| missing("OptionGroupName"))?;
                let mut accounts = write_state!();
                let state = accounts.get_or_create(&aid);
                if let Some(m) = state.extras.get_mut("option_groups") { m.remove(&name); }
                xml_empty_action(&action, &rid)
            }
            "DescribeOptionGroups" => list_extras_xml(self, &aid, "option_groups", "OptionGroupsList", "DescribeOptionGroups", option_group_xml, &rid),
            "DescribeOptionGroupOptions" => Ok(xml_response("DescribeOptionGroupOptions", "    <OptionGroupOptions/>".to_string(), &rid)),

            // ── Event subscriptions ──
            "CreateEventSubscription" => {
                let name = get_param(req, "SubscriptionName").ok_or_else(|| missing("SubscriptionName"))?;
                let entry = json!({"CustSubscriptionId": name, "SnsTopicArn": get_param(req, "SnsTopicArn").unwrap_or_default(), "Status": "active", "Enabled": true});
                let mut accounts = write_state!();
                let state = accounts.get_or_create(&aid);
                store(&mut state.extras, "event_subscriptions").insert(name.clone(), entry.clone());
                Ok(xml_response("CreateEventSubscription", event_sub_xml(&entry), &rid))
            }
            "ModifyEventSubscription" => Ok(xml_response("ModifyEventSubscription", "    <EventSubscription/>".to_string(), &rid)),
            "DeleteEventSubscription" => {
                let name = get_param(req, "SubscriptionName").ok_or_else(|| missing("SubscriptionName"))?;
                let mut accounts = write_state!();
                let state = accounts.get_or_create(&aid);
                if let Some(m) = state.extras.get_mut("event_subscriptions") { m.remove(&name); }
                Ok(xml_response("DeleteEventSubscription", "    <EventSubscription/>".to_string(), &rid))
            }
            "DescribeEventSubscriptions" => list_extras_xml(self, &aid, "event_subscriptions", "EventSubscriptionsList", "DescribeEventSubscriptions", event_sub_xml, &rid),
            "AddSourceIdentifierToSubscription" | "RemoveSourceIdentifierFromSubscription" => Ok(xml_response(action.as_str(), "    <EventSubscription/>".to_string(), &rid)),

            // ── Global clusters ──
            "CreateGlobalCluster" => {
                let id = get_param(req, "GlobalClusterIdentifier").ok_or_else(|| missing("GlobalClusterIdentifier"))?;
                let arn = format!("arn:aws:rds::{aid}:global-cluster:{id}");
                let entry = json!({"GlobalClusterIdentifier": id, "GlobalClusterArn": arn, "Status": "available"});
                let mut accounts = write_state!();
                let state = accounts.get_or_create(&aid);
                store(&mut state.extras, "global_clusters").insert(id.clone(), entry.clone());
                Ok(xml_response("CreateGlobalCluster", global_cluster_xml(&entry), &rid))
            }
            "ModifyGlobalCluster" | "FailoverGlobalCluster" | "SwitchoverGlobalCluster" | "RemoveFromGlobalCluster" => Ok(xml_response(action.as_str(), "    <GlobalCluster/>".to_string(), &rid)),
            "DeleteGlobalCluster" => {
                let id = get_param(req, "GlobalClusterIdentifier").ok_or_else(|| missing("GlobalClusterIdentifier"))?;
                let mut accounts = write_state!();
                let state = accounts.get_or_create(&aid);
                if let Some(m) = state.extras.get_mut("global_clusters") { m.remove(&id); }
                Ok(xml_response("DeleteGlobalCluster", "    <GlobalCluster/>".to_string(), &rid))
            }
            "DescribeGlobalClusters" => list_extras_xml(self, &aid, "global_clusters", "GlobalClusters", "DescribeGlobalClusters", global_cluster_xml, &rid),

            // ── Integrations ──
            "CreateIntegration" => {
                let name = get_param(req, "IntegrationName").ok_or_else(|| missing("IntegrationName"))?;
                let arn = format!("arn:aws:rds:{region}:{aid}:integration:{name}");
                let entry = json!({"IntegrationName": name, "IntegrationArn": arn, "Status": "active"});
                let mut accounts = write_state!();
                let state = accounts.get_or_create(&aid);
                store(&mut state.extras, "integrations").insert(name.clone(), entry.clone());
                Ok(xml_response("CreateIntegration", integration_xml(&entry), &rid))
            }
            "ModifyIntegration" => Ok(xml_response("ModifyIntegration", "    <Integration/>".to_string(), &rid)),
            "DeleteIntegration" => {
                let name = get_param(req, "IntegrationIdentifier").or_else(|| get_param(req, "IntegrationName")).ok_or_else(|| missing("IntegrationIdentifier"))?;
                let mut accounts = write_state!();
                let state = accounts.get_or_create(&aid);
                if let Some(m) = state.extras.get_mut("integrations") { m.remove(&name); }
                Ok(xml_response("DeleteIntegration", "    <Integration/>".to_string(), &rid))
            }
            "DescribeIntegrations" => list_extras_xml(self, &aid, "integrations", "Integrations", "DescribeIntegrations", integration_xml, &rid),

            // ── Blue/Green deployments ──
            "CreateBlueGreenDeployment" => {
                let id = format!("bgd-{}", rand_id());
                let entry = json!({"BlueGreenDeploymentIdentifier": id, "BlueGreenDeploymentName": get_param(req, "BlueGreenDeploymentName").unwrap_or_else(|| "blue-green".to_string()), "Status": "AVAILABLE"});
                let mut accounts = write_state!();
                let state = accounts.get_or_create(&aid);
                store(&mut state.extras, "blue_green").insert(id.clone(), entry.clone());
                Ok(xml_response("CreateBlueGreenDeployment", blue_green_xml(&entry), &rid))
            }
            "SwitchoverBlueGreenDeployment" => Ok(xml_response("SwitchoverBlueGreenDeployment", "    <BlueGreenDeployment/>".to_string(), &rid)),
            "DeleteBlueGreenDeployment" => Ok(xml_response("DeleteBlueGreenDeployment", "    <BlueGreenDeployment/>".to_string(), &rid)),
            "DescribeBlueGreenDeployments" => list_extras_xml(self, &aid, "blue_green", "BlueGreenDeployments", "DescribeBlueGreenDeployments", blue_green_xml, &rid),

            // ── Shard groups ──
            "CreateDBShardGroup" => {
                let id = get_param(req, "DBShardGroupIdentifier").ok_or_else(|| missing("DBShardGroupIdentifier"))?;
                let entry = json!({"DBShardGroupIdentifier": id, "Status": "available"});
                let mut accounts = write_state!();
                let state = accounts.get_or_create(&aid);
                store(&mut state.extras, "shard_groups").insert(id.clone(), entry.clone());
                Ok(xml_response("CreateDBShardGroup", shard_group_xml(&entry), &rid))
            }
            "ModifyDBShardGroup" | "RebootDBShardGroup" => Ok(xml_response(action.as_str(), "    <DBShardGroup/>".to_string(), &rid)),
            "DeleteDBShardGroup" => {
                let id = get_param(req, "DBShardGroupIdentifier").ok_or_else(|| missing("DBShardGroupIdentifier"))?;
                let mut accounts = write_state!();
                let state = accounts.get_or_create(&aid);
                if let Some(m) = state.extras.get_mut("shard_groups") { m.remove(&id); }
                Ok(xml_response("DeleteDBShardGroup", "    <DBShardGroup/>".to_string(), &rid))
            }
            "DescribeDBShardGroups" => list_extras_xml(self, &aid, "shard_groups", "DBShardGroups", "DescribeDBShardGroups", shard_group_xml, &rid),

            // ── Custom engine versions ──
            "CreateCustomDBEngineVersion" | "ModifyCustomDBEngineVersion" => {
                let v = get_param(req, "EngineVersion").unwrap_or_else(|| "1.0".to_string());
                let engine = get_param(req, "Engine").unwrap_or_else(|| "custom-oracle-ee".to_string());
                let entry = json!({"Engine": engine, "EngineVersion": v, "Status": "available"});
                let mut accounts = write_state!();
                let state = accounts.get_or_create(&aid);
                store(&mut state.extras, "custom_engine_versions").insert(v.clone(), entry.clone());
                Ok(xml_response(action.as_str(), engine_version_xml(&entry), &rid))
            }
            "DeleteCustomDBEngineVersion" => Ok(xml_response("DeleteCustomDBEngineVersion", "    <DBEngineVersion/>".to_string(), &rid)),

            // ── Tenant databases ──
            "CreateTenantDatabase" => {
                let name = get_param(req, "TenantDBName").ok_or_else(|| missing("TenantDBName"))?;
                let entry = json!({"TenantDBName": name, "Status": "available"});
                let mut accounts = write_state!();
                let state = accounts.get_or_create(&aid);
                store(&mut state.extras, "tenant_dbs").insert(name.clone(), entry.clone());
                Ok(xml_response("CreateTenantDatabase", tenant_db_xml(&entry), &rid))
            }
            "ModifyTenantDatabase" => Ok(xml_response("ModifyTenantDatabase", "    <TenantDatabase/>".to_string(), &rid)),
            "DeleteTenantDatabase" => {
                let name = get_param(req, "TenantDBName").ok_or_else(|| missing("TenantDBName"))?;
                let mut accounts = write_state!();
                let state = accounts.get_or_create(&aid);
                if let Some(m) = state.extras.get_mut("tenant_dbs") { m.remove(&name); }
                Ok(xml_response("DeleteTenantDatabase", "    <TenantDatabase/>".to_string(), &rid))
            }
            "DescribeTenantDatabases" => list_extras_xml(self, &aid, "tenant_dbs", "TenantDatabases", "DescribeTenantDatabases", tenant_db_xml, &rid),
            "DescribeDBSnapshotTenantDatabases" => Ok(xml_response("DescribeDBSnapshotTenantDatabases", "    <DBSnapshotTenantDatabases/>".to_string(), &rid)),

            // ── Export tasks ──
            "StartExportTask" => {
                let id = get_param(req, "ExportTaskIdentifier").ok_or_else(|| missing("ExportTaskIdentifier"))?;
                let entry = json!({"ExportTaskIdentifier": id, "Status": "STARTING"});
                let mut accounts = write_state!();
                let state = accounts.get_or_create(&aid);
                store(&mut state.extras, "export_tasks").insert(id.clone(), entry.clone());
                Ok(xml_response("StartExportTask", export_task_xml(&entry), &rid))
            }
            "CancelExportTask" => Ok(xml_response("CancelExportTask", "    <ExportTask/>".to_string(), &rid)),
            "DescribeExportTasks" => list_extras_xml(self, &aid, "export_tasks", "ExportTasks", "DescribeExportTasks", export_task_xml, &rid),

            // ── Activity stream ──
            "StartActivityStream" => Ok(xml_response("StartActivityStream", "    <Status>started</Status>\n    <KmsKeyId>arn:aws:kms::us-east-1:000:key/x</KmsKeyId>\n    <KinesisStreamName>aws-rds-das-x</KinesisStreamName>".to_string(), &rid)),
            "StopActivityStream" => Ok(xml_response("StopActivityStream", "    <Status>stopped</Status>".to_string(), &rid)),
            "ModifyActivityStream" => Ok(xml_response("ModifyActivityStream", "    <Status>started</Status>".to_string(), &rid)),

            // ── Database read replicas ──
            "PromoteReadReplica" => Ok(xml_response("PromoteReadReplica", "    <DBInstance/>".to_string(), &rid)),
            "StartDBInstance" | "StopDBInstance" => {
                if let Some(id) = get_param(req, "DBInstanceIdentifier") {
                    let (event_id, categories, msg) = if action == "StartDBInstance" {
                        ("RDS-EVENT-0088", ["notification"], "DB instance started")
                    } else {
                        ("RDS-EVENT-0089", ["notification"], "DB instance stopped")
                    };
                    let arn = {
                        let accounts = self.state_handle().read();
                        accounts
                            .get(&aid)
                            .and_then(|s| s.instances.get(&id).map(|i| i.db_instance_arn.clone()))
                            .unwrap_or_else(|| {
                                format!("arn:aws:rds:{region}:{aid}:db:{id}")
                            })
                    };
                    self.emit_event(
                        RdsSourceType::DbInstance,
                        &id,
                        &arn,
                        event_id,
                        &categories,
                        msg,
                    );
                }
                Ok(xml_response(action.as_str(), "    <DBInstance/>".to_string(), &rid))
            }
            "StartDBInstanceAutomatedBackupsReplication" | "StopDBInstanceAutomatedBackupsReplication" => Ok(xml_response(action.as_str(), "    <DBInstanceAutomatedBackup/>".to_string(), &rid)),
            "DeleteDBInstanceAutomatedBackup" => Ok(xml_response("DeleteDBInstanceAutomatedBackup", "    <DBInstanceAutomatedBackup/>".to_string(), &rid)),
            "DescribeDBInstanceAutomatedBackups" => Ok(xml_response("DescribeDBInstanceAutomatedBackups", "    <DBInstanceAutomatedBackups/>".to_string(), &rid)),

            // ── Roles ──
            "AddRoleToDBCluster" | "RemoveRoleFromDBCluster" | "AddRoleToDBInstance" | "RemoveRoleFromDBInstance" => xml_empty_action(&action, &rid),

            // ── Pending maintenance ──
            "ApplyPendingMaintenanceAction" => Ok(xml_response("ApplyPendingMaintenanceAction", "    <ResourcePendingMaintenanceActions/>".to_string(), &rid)),
            "DescribePendingMaintenanceActions" => Ok(xml_response("DescribePendingMaintenanceActions", "    <PendingMaintenanceActions/>".to_string(), &rid)),

            // ── Reserved instances ──
            "PurchaseReservedDBInstancesOffering" => Ok(xml_response("PurchaseReservedDBInstancesOffering", "    <ReservedDBInstance/>".to_string(), &rid)),
            "DescribeReservedDBInstances" => Ok(xml_response("DescribeReservedDBInstances", "    <ReservedDBInstances/>".to_string(), &rid)),
            "DescribeReservedDBInstancesOfferings" => Ok(xml_response("DescribeReservedDBInstancesOfferings", "    <ReservedDBInstancesOfferings/>".to_string(), &rid)),

            // ── Snapshots / restores / copy ──
            "CopyDBSnapshot" => {
                let id = get_param(req, "TargetDBSnapshotIdentifier").ok_or_else(|| missing("TargetDBSnapshotIdentifier"))?;
                Ok(xml_response("CopyDBSnapshot", format!("    <DBSnapshot>\n      <DBSnapshotIdentifier>{}</DBSnapshotIdentifier>\n      <Status>available</Status>\n    </DBSnapshot>", xml_escape(&id)), &rid))
            }
            "CopyDBParameterGroup" => {
                let name = get_param(req, "TargetDBParameterGroupIdentifier").ok_or_else(|| missing("TargetDBParameterGroupIdentifier"))?;
                Ok(xml_response("CopyDBParameterGroup", format!("    <DBParameterGroup>\n      <DBParameterGroupName>{}</DBParameterGroupName>\n    </DBParameterGroup>", xml_escape(&name)), &rid))
            }
            "DescribeDBParameters" => Ok(xml_response("DescribeDBParameters", "    <Parameters/>".to_string(), &rid)),
            "ResetDBParameterGroup" => {
                let name = get_param(req, "DBParameterGroupName").ok_or_else(|| missing("DBParameterGroupName"))?;
                Ok(xml_response("ResetDBParameterGroup", format!("    <DBParameterGroupName>{}</DBParameterGroupName>", xml_escape(&name)), &rid))
            }
            "DescribeEngineDefaultParameters" => Ok(xml_response("DescribeEngineDefaultParameters", "    <EngineDefaults>\n      <Parameters/>\n    </EngineDefaults>".to_string(), &rid)),
            "DescribeDBSnapshotAttributes" => Ok(xml_response("DescribeDBSnapshotAttributes", "    <DBSnapshotAttributesResult>\n      <DBSnapshotAttributes/>\n    </DBSnapshotAttributesResult>".to_string(), &rid)),
            "ModifyDBSnapshot" | "ModifyDBSnapshotAttribute" => Ok(xml_response(action.as_str(), "    <DBSnapshot/>".to_string(), &rid)),
            "RestoreDBClusterFromS3" | "RestoreDBClusterFromSnapshot" | "RestoreDBClusterToPointInTime" => Ok(xml_response(action.as_str(), "    <DBCluster/>".to_string(), &rid)),
            "RestoreDBInstanceFromS3" | "RestoreDBInstanceToPointInTime" => Ok(xml_response(action.as_str(), "    <DBInstance/>".to_string(), &rid)),

            // ── Recommendations ──
            "DescribeDBRecommendations" => Ok(xml_response("DescribeDBRecommendations", "    <DBRecommendations/>".to_string(), &rid)),
            "ModifyDBRecommendation" => Ok(xml_response("ModifyDBRecommendation", "    <DBRecommendation/>".to_string(), &rid)),

            // ── Certificates ──
            "DescribeCertificates" => Ok(xml_response("DescribeCertificates", "    <Certificates/>".to_string(), &rid)),
            "ModifyCertificates" => Ok(xml_response("ModifyCertificates", "    <Certificate/>".to_string(), &rid)),

            // ── Account / events / regions / log files / capacity ──
            "DescribeAccountAttributes" => Ok(xml_response("DescribeAccountAttributes", "    <AccountQuotas/>".to_string(), &rid)),
            "DescribeEventCategories" => Ok(xml_response("DescribeEventCategories", "    <EventCategoriesMapList/>".to_string(), &rid)),
            "DescribeEvents" => Ok(xml_response("DescribeEvents", "    <Events/>".to_string(), &rid)),
            "DescribeSourceRegions" => Ok(xml_response("DescribeSourceRegions", "    <SourceRegions/>".to_string(), &rid)),
            "DescribeDBLogFiles" => Ok(xml_response("DescribeDBLogFiles", "    <DescribeDBLogFiles/>".to_string(), &rid)),
            "DownloadDBLogFilePortion" => Ok(xml_response("DownloadDBLogFilePortion", "    <LogFileData></LogFileData>\n    <Marker>0</Marker>\n    <AdditionalDataPending>false</AdditionalDataPending>".to_string(), &rid)),
            "DescribeDBMajorEngineVersions" => Ok(xml_response("DescribeDBMajorEngineVersions", "    <DBMajorEngineVersions/>".to_string(), &rid)),
            "DescribeValidDBInstanceModifications" => Ok(xml_response("DescribeValidDBInstanceModifications", "    <ValidDBInstanceModificationsMessage>\n      <ValidProcessorFeatures/>\n      <Storage/>\n    </ValidDBInstanceModificationsMessage>".to_string(), &rid)),
            "ModifyCurrentDBClusterCapacity" => Ok(xml_response("ModifyCurrentDBClusterCapacity", "    <DBClusterIdentifier>x</DBClusterIdentifier>\n    <CurrentCapacity>4</CurrentCapacity>".to_string(), &rid)),
            "DisableHttpEndpoint" => Ok(xml_response("DisableHttpEndpoint", "    <HttpEndpointEnabled>false</HttpEndpointEnabled>".to_string(), &rid)),
            "EnableHttpEndpoint" => Ok(xml_response("EnableHttpEndpoint", "    <HttpEndpointEnabled>true</HttpEndpointEnabled>".to_string(), &rid)),

            // ── Read replicas ──
            "SwitchoverReadReplica" => Ok(xml_response("SwitchoverReadReplica", "    <DBInstance/>".to_string(), &rid)),

            _ => Err(AwsServiceError::action_not_implemented("rds", &action)),
        }
    }
}

// ── XML helpers per resource ──

fn db_cluster_xml(id: &str, arn: &str) -> String {
    format!(
        "    <DBCluster>\n      <DBClusterIdentifier>{}</DBClusterIdentifier>\n      <DBClusterArn>{}</DBClusterArn>\n      <Status>available</Status>\n    </DBCluster>",
        xml_escape(id), xml_escape(arn)
    )
}

fn db_cluster_member_xml(v: &Value) -> String {
    format!(
        "          <DBClusterIdentifier>{}</DBClusterIdentifier>\n          <DBClusterArn>{}</DBClusterArn>\n          <Status>{}</Status>",
        xml_escape(v["DBClusterIdentifier"].as_str().unwrap_or("")),
        xml_escape(v["DBClusterArn"].as_str().unwrap_or("")),
        xml_escape(v["Status"].as_str().unwrap_or("available")),
    )
}

fn cluster_snapshot_xml(id: &str, arn: &str, cluster: &str) -> String {
    format!(
        "    <DBClusterSnapshot>\n      <DBClusterSnapshotIdentifier>{}</DBClusterSnapshotIdentifier>\n      <DBClusterSnapshotArn>{}</DBClusterSnapshotArn>\n      <DBClusterIdentifier>{}</DBClusterIdentifier>\n      <Status>available</Status>\n    </DBClusterSnapshot>",
        xml_escape(id), xml_escape(arn), xml_escape(cluster),
    )
}

fn cluster_snapshot_member_xml(v: &Value) -> String {
    format!(
        "          <DBClusterSnapshotIdentifier>{}</DBClusterSnapshotIdentifier>\n          <DBClusterSnapshotArn>{}</DBClusterSnapshotArn>\n          <DBClusterIdentifier>{}</DBClusterIdentifier>\n          <Status>{}</Status>",
        xml_escape(v["DBClusterSnapshotIdentifier"].as_str().unwrap_or("")),
        xml_escape(v["DBClusterSnapshotArn"].as_str().unwrap_or("")),
        xml_escape(v["DBClusterIdentifier"].as_str().unwrap_or("")),
        xml_escape(v["Status"].as_str().unwrap_or("available")),
    )
}

fn cluster_pg_xml(name: &str, arn: &str, family: &str) -> String {
    format!(
        "    <DBClusterParameterGroup>\n      <DBClusterParameterGroupName>{}</DBClusterParameterGroupName>\n      <DBClusterParameterGroupArn>{}</DBClusterParameterGroupArn>\n      <DBParameterGroupFamily>{}</DBParameterGroupFamily>\n    </DBClusterParameterGroup>",
        xml_escape(name), xml_escape(arn), xml_escape(family),
    )
}

fn cluster_pg_member_xml(v: &Value) -> String {
    format!(
        "          <DBClusterParameterGroupName>{}</DBClusterParameterGroupName>\n          <DBClusterParameterGroupArn>{}</DBClusterParameterGroupArn>\n          <DBParameterGroupFamily>{}</DBParameterGroupFamily>",
        xml_escape(v["DBClusterParameterGroupName"].as_str().unwrap_or("")),
        xml_escape(v["DBClusterParameterGroupArn"].as_str().unwrap_or("")),
        xml_escape(v["DBParameterGroupFamily"].as_str().unwrap_or("")),
    )
}

fn cluster_endpoint_xml(v: &Value) -> String {
    format!(
        "          <DBClusterEndpointIdentifier>{}</DBClusterEndpointIdentifier>\n          <DBClusterIdentifier>{}</DBClusterIdentifier>\n          <Endpoint>{}</Endpoint>\n          <EndpointType>{}</EndpointType>\n          <Status>{}</Status>",
        xml_escape(v["DBClusterEndpointIdentifier"].as_str().unwrap_or("")),
        xml_escape(v["DBClusterIdentifier"].as_str().unwrap_or("")),
        xml_escape(v["Endpoint"].as_str().unwrap_or("")),
        xml_escape(v["EndpointType"].as_str().unwrap_or("")),
        xml_escape(v["Status"].as_str().unwrap_or("available")),
    )
}

fn proxy_xml(v: &Value) -> String {
    format!(
        "          <DBProxyName>{}</DBProxyName>\n          <DBProxyArn>{}</DBProxyArn>\n          <Status>{}</Status>\n          <EngineFamily>{}</EngineFamily>",
        xml_escape(v["DBProxyName"].as_str().unwrap_or("")),
        xml_escape(v["DBProxyArn"].as_str().unwrap_or("")),
        xml_escape(v["Status"].as_str().unwrap_or("available")),
        xml_escape(v["EngineFamily"].as_str().unwrap_or("POSTGRESQL")),
    )
}

fn security_group_xml(v: &Value) -> String {
    format!(
        "          <DBSecurityGroupName>{}</DBSecurityGroupName>\n          <DBSecurityGroupDescription>{}</DBSecurityGroupDescription>\n          <OwnerId>{}</OwnerId>",
        xml_escape(v["DBSecurityGroupName"].as_str().unwrap_or("")),
        xml_escape(v["DBSecurityGroupDescription"].as_str().unwrap_or("")),
        xml_escape(v["OwnerId"].as_str().unwrap_or("000000000000")),
    )
}

fn option_group_xml(v: &Value) -> String {
    format!(
        "          <OptionGroupName>{}</OptionGroupName>\n          <OptionGroupArn>{}</OptionGroupArn>\n          <EngineName>{}</EngineName>\n          <MajorEngineVersion>{}</MajorEngineVersion>",
        xml_escape(v["OptionGroupName"].as_str().unwrap_or("")),
        xml_escape(v["OptionGroupArn"].as_str().unwrap_or("")),
        xml_escape(v["EngineName"].as_str().unwrap_or("")),
        xml_escape(v["MajorEngineVersion"].as_str().unwrap_or("")),
    )
}

fn event_sub_xml(v: &Value) -> String {
    format!(
        "          <CustSubscriptionId>{}</CustSubscriptionId>\n          <SnsTopicArn>{}</SnsTopicArn>\n          <Status>{}</Status>\n          <Enabled>{}</Enabled>",
        xml_escape(v["CustSubscriptionId"].as_str().unwrap_or("")),
        xml_escape(v["SnsTopicArn"].as_str().unwrap_or("")),
        xml_escape(v["Status"].as_str().unwrap_or("active")),
        v["Enabled"].as_bool().unwrap_or(true),
    )
}

fn global_cluster_xml(v: &Value) -> String {
    format!(
        "          <GlobalClusterIdentifier>{}</GlobalClusterIdentifier>\n          <GlobalClusterArn>{}</GlobalClusterArn>\n          <Status>{}</Status>",
        xml_escape(v["GlobalClusterIdentifier"].as_str().unwrap_or("")),
        xml_escape(v["GlobalClusterArn"].as_str().unwrap_or("")),
        xml_escape(v["Status"].as_str().unwrap_or("available")),
    )
}

fn integration_xml(v: &Value) -> String {
    format!(
        "          <IntegrationName>{}</IntegrationName>\n          <IntegrationArn>{}</IntegrationArn>\n          <Status>{}</Status>",
        xml_escape(v["IntegrationName"].as_str().unwrap_or("")),
        xml_escape(v["IntegrationArn"].as_str().unwrap_or("")),
        xml_escape(v["Status"].as_str().unwrap_or("active")),
    )
}

fn blue_green_xml(v: &Value) -> String {
    format!(
        "          <BlueGreenDeploymentIdentifier>{}</BlueGreenDeploymentIdentifier>\n          <BlueGreenDeploymentName>{}</BlueGreenDeploymentName>\n          <Status>{}</Status>",
        xml_escape(v["BlueGreenDeploymentIdentifier"].as_str().unwrap_or("")),
        xml_escape(v["BlueGreenDeploymentName"].as_str().unwrap_or("")),
        xml_escape(v["Status"].as_str().unwrap_or("AVAILABLE")),
    )
}

fn shard_group_xml(v: &Value) -> String {
    format!(
        "          <DBShardGroupIdentifier>{}</DBShardGroupIdentifier>\n          <Status>{}</Status>",
        xml_escape(v["DBShardGroupIdentifier"].as_str().unwrap_or("")),
        xml_escape(v["Status"].as_str().unwrap_or("available")),
    )
}

fn engine_version_xml(v: &Value) -> String {
    format!(
        "    <DBEngineVersion>\n      <Engine>{}</Engine>\n      <EngineVersion>{}</EngineVersion>\n      <Status>{}</Status>\n    </DBEngineVersion>",
        xml_escape(v["Engine"].as_str().unwrap_or("")),
        xml_escape(v["EngineVersion"].as_str().unwrap_or("")),
        xml_escape(v["Status"].as_str().unwrap_or("available")),
    )
}

fn tenant_db_xml(v: &Value) -> String {
    format!(
        "          <TenantDBName>{}</TenantDBName>\n          <Status>{}</Status>",
        xml_escape(v["TenantDBName"].as_str().unwrap_or("")),
        xml_escape(v["Status"].as_str().unwrap_or("available")),
    )
}

fn export_task_xml(v: &Value) -> String {
    format!(
        "          <ExportTaskIdentifier>{}</ExportTaskIdentifier>\n          <Status>{}</Status>",
        xml_escape(v["ExportTaskIdentifier"].as_str().unwrap_or("")),
        xml_escape(v["Status"].as_str().unwrap_or("STARTING")),
    )
}

fn xml_empty_action(action: &str, request_id: &str) -> Result<AwsResponse, AwsServiceError> {
    Ok(xml_response_no_result(action, request_id))
}

fn list_extras_xml(
    svc: &RdsService,
    aid: &str,
    category: &str,
    wrapper: &str,
    action: &str,
    render: impl Fn(&Value) -> String,
    rid: &str,
) -> Result<AwsResponse, AwsServiceError> {
    let accounts = svc.state_handle().read();
    let items: Vec<Value> = accounts
        .get(aid)
        .and_then(|s| s.extras.get(category))
        .map(|m| m.values().cloned().collect())
        .unwrap_or_default();
    let inner = format!(
        "    <{wrapper}>\n{}\n    </{wrapper}>",
        members(&items, render)
    );
    Ok(xml_response(action, inner, rid))
}

#[cfg(test)]
mod tests {
    use crate::service::RdsService;
    use crate::state::{RdsState, SharedRdsState};
    use fakecloud_core::multi_account::MultiAccountState;
    use fakecloud_core::service::AwsRequest;
    use http::Method;
    use parking_lot::RwLock;
    use std::collections::HashMap;
    use std::sync::Arc;

    fn svc() -> RdsService {
        let state: SharedRdsState = Arc::new(RwLock::new(MultiAccountState::<RdsState>::new(
            "000000000000",
            "us-east-1",
            "",
        )));
        RdsService::new(state)
    }

    fn req(action: &str, params: &[(&str, &str)]) -> AwsRequest {
        let mut q = HashMap::new();
        q.insert("Action".to_string(), action.to_string());
        for (k, v) in params {
            q.insert(k.to_string(), v.to_string());
        }
        AwsRequest {
            service: "rds".to_string(),
            method: Method::POST,
            raw_path: "/".to_string(),
            raw_query: String::new(),
            path_segments: vec![],
            query_params: q,
            headers: http::HeaderMap::new(),
            body: bytes::Bytes::new(),
            body_stream: parking_lot::Mutex::new(None),
            account_id: "000000000000".to_string(),
            region: "us-east-1".to_string(),
            request_id: "rid".to_string(),
            action: action.to_string(),
            is_query_protocol: true,
            access_key_id: None,
            principal: None,
        }
    }

    fn ok(action: &str, params: &[(&str, &str)]) {
        let r = svc().handle_extra_action(&req(action, params));
        let resp = match r {
            Ok(r) => r,
            Err(e) => panic!("{action} failed: {e:?}"),
        };
        assert!(resp.status.is_success(), "{action} status: {}", resp.status);
    }

    #[test]
    fn cluster_lifecycle() {
        ok("CreateDBCluster", &[("DBClusterIdentifier", "c1")]);
        ok("ModifyDBCluster", &[("DBClusterIdentifier", "c1")]);
        ok("RebootDBCluster", &[("DBClusterIdentifier", "c1")]);
        ok("StartDBCluster", &[("DBClusterIdentifier", "c1")]);
        ok("StopDBCluster", &[("DBClusterIdentifier", "c1")]);
        ok("FailoverDBCluster", &[("DBClusterIdentifier", "c1")]);
        ok("BacktrackDBCluster", &[("DBClusterIdentifier", "c1")]);
        ok(
            "PromoteReadReplicaDBCluster",
            &[("DBClusterIdentifier", "c1")],
        );
        ok("DescribeDBClusters", &[]);
        ok("DeleteDBCluster", &[("DBClusterIdentifier", "c1")]);
    }

    #[test]
    fn cluster_snapshot_lifecycle() {
        ok(
            "CreateDBClusterSnapshot",
            &[
                ("DBClusterSnapshotIdentifier", "cs1"),
                ("DBClusterIdentifier", "c1"),
            ],
        );
        ok(
            "CopyDBClusterSnapshot",
            &[("TargetDBClusterSnapshotIdentifier", "cs2")],
        );
        ok("DescribeDBClusterSnapshots", &[]);
        ok(
            "DescribeDBClusterSnapshotAttributes",
            &[("DBClusterSnapshotIdentifier", "cs1")],
        );
        ok(
            "ModifyDBClusterSnapshotAttribute",
            &[("DBClusterSnapshotIdentifier", "cs1")],
        );
        ok("DescribeDBClusterAutomatedBackups", &[]);
        ok("DeleteDBClusterAutomatedBackup", &[]);
        ok("DescribeDBClusterBacktracks", &[]);
        ok(
            "DeleteDBClusterSnapshot",
            &[("DBClusterSnapshotIdentifier", "cs1")],
        );
    }

    #[test]
    fn cluster_param_groups_lifecycle() {
        ok(
            "CreateDBClusterParameterGroup",
            &[("DBClusterParameterGroupName", "cpg")],
        );
        ok(
            "CopyDBClusterParameterGroup",
            &[("TargetDBClusterParameterGroupIdentifier", "cpg2")],
        );
        ok(
            "ModifyDBClusterParameterGroup",
            &[("DBClusterParameterGroupName", "cpg")],
        );
        ok(
            "ResetDBClusterParameterGroup",
            &[("DBClusterParameterGroupName", "cpg")],
        );
        ok("DescribeDBClusterParameterGroups", &[]);
        ok("DescribeDBClusterParameters", &[]);
        ok("DescribeEngineDefaultClusterParameters", &[]);
        ok(
            "DeleteDBClusterParameterGroup",
            &[("DBClusterParameterGroupName", "cpg")],
        );
    }

    #[test]
    fn endpoints_proxies_secgroups() {
        ok(
            "CreateDBClusterEndpoint",
            &[("DBClusterEndpointIdentifier", "ce1")],
        );
        ok("ModifyDBClusterEndpoint", &[]);
        ok("DescribeDBClusterEndpoints", &[]);
        ok(
            "DeleteDBClusterEndpoint",
            &[("DBClusterEndpointIdentifier", "ce1")],
        );
        ok("CreateDBProxy", &[("DBProxyName", "p1")]);
        ok("DescribeDBProxies", &[]);
        ok("CreateDBProxyEndpoint", &[("DBProxyEndpointName", "pe1")]);
        ok("ModifyDBProxyEndpoint", &[]);
        ok("DescribeDBProxyEndpoints", &[]);
        ok("DescribeDBProxyTargetGroups", &[]);
        ok("DescribeDBProxyTargets", &[]);
        ok("ModifyDBProxyTargetGroup", &[]);
        ok("RegisterDBProxyTargets", &[]);
        ok("DeregisterDBProxyTargets", &[]);
        ok("DeleteDBProxyEndpoint", &[("DBProxyEndpointName", "pe1")]);
        ok("ModifyDBProxy", &[]);
        ok("DeleteDBProxy", &[("DBProxyName", "p1")]);
        ok("CreateDBSecurityGroup", &[("DBSecurityGroupName", "sg1")]);
        ok(
            "AuthorizeDBSecurityGroupIngress",
            &[("DBSecurityGroupName", "sg1")],
        );
        ok(
            "RevokeDBSecurityGroupIngress",
            &[("DBSecurityGroupName", "sg1")],
        );
        ok("DescribeDBSecurityGroups", &[]);
        ok("DeleteDBSecurityGroup", &[("DBSecurityGroupName", "sg1")]);
    }

    #[test]
    fn option_groups_event_subs_global_clusters() {
        ok("CreateOptionGroup", &[("OptionGroupName", "og1")]);
        ok("ModifyOptionGroup", &[("OptionGroupName", "og1")]);
        ok("CopyOptionGroup", &[("TargetOptionGroupIdentifier", "og2")]);
        ok("DescribeOptionGroups", &[]);
        ok("DescribeOptionGroupOptions", &[]);
        ok("DeleteOptionGroup", &[("OptionGroupName", "og1")]);
        ok("CreateEventSubscription", &[("SubscriptionName", "es1")]);
        ok("ModifyEventSubscription", &[]);
        ok("AddSourceIdentifierToSubscription", &[]);
        ok("RemoveSourceIdentifierFromSubscription", &[]);
        ok("DescribeEventSubscriptions", &[]);
        ok("DeleteEventSubscription", &[("SubscriptionName", "es1")]);
        ok("CreateGlobalCluster", &[("GlobalClusterIdentifier", "gc1")]);
        ok("ModifyGlobalCluster", &[]);
        ok("FailoverGlobalCluster", &[]);
        ok("SwitchoverGlobalCluster", &[]);
        ok("RemoveFromGlobalCluster", &[]);
        ok("DescribeGlobalClusters", &[]);
        ok("DeleteGlobalCluster", &[("GlobalClusterIdentifier", "gc1")]);
    }

    #[test]
    fn integrations_blue_green_shard_groups_tenant_dbs() {
        ok("CreateIntegration", &[("IntegrationName", "i1")]);
        ok("ModifyIntegration", &[]);
        ok("DescribeIntegrations", &[]);
        ok("DeleteIntegration", &[("IntegrationIdentifier", "i1")]);
        ok("CreateBlueGreenDeployment", &[]);
        ok("SwitchoverBlueGreenDeployment", &[]);
        ok("DeleteBlueGreenDeployment", &[]);
        ok("DescribeBlueGreenDeployments", &[]);
        ok("CreateDBShardGroup", &[("DBShardGroupIdentifier", "sg1")]);
        ok("ModifyDBShardGroup", &[]);
        ok("RebootDBShardGroup", &[]);
        ok("DescribeDBShardGroups", &[]);
        ok("DeleteDBShardGroup", &[("DBShardGroupIdentifier", "sg1")]);
        ok("CreateCustomDBEngineVersion", &[]);
        ok("ModifyCustomDBEngineVersion", &[]);
        ok("DeleteCustomDBEngineVersion", &[]);
        ok("CreateTenantDatabase", &[("TenantDBName", "t1")]);
        ok("ModifyTenantDatabase", &[]);
        ok("DescribeTenantDatabases", &[]);
        ok("DescribeDBSnapshotTenantDatabases", &[]);
        ok("DeleteTenantDatabase", &[("TenantDBName", "t1")]);
    }

    #[test]
    fn export_activity_replicas_recommendations_certs_pending() {
        ok("StartExportTask", &[("ExportTaskIdentifier", "ex1")]);
        ok("CancelExportTask", &[]);
        ok("DescribeExportTasks", &[]);
        ok("StartActivityStream", &[]);
        ok("ModifyActivityStream", &[]);
        ok("StopActivityStream", &[]);
        ok("AddRoleToDBCluster", &[]);
        ok("RemoveRoleFromDBCluster", &[]);
        ok("AddRoleToDBInstance", &[]);
        ok("RemoveRoleFromDBInstance", &[]);
        ok("ApplyPendingMaintenanceAction", &[]);
        ok("DescribePendingMaintenanceActions", &[]);
        ok("PurchaseReservedDBInstancesOffering", &[]);
        ok("DescribeReservedDBInstances", &[]);
        ok("DescribeReservedDBInstancesOfferings", &[]);
        ok("PromoteReadReplica", &[]);
        ok("StartDBInstance", &[]);
        ok("StopDBInstance", &[]);
        ok("StartDBInstanceAutomatedBackupsReplication", &[]);
        ok("StopDBInstanceAutomatedBackupsReplication", &[]);
        ok("DeleteDBInstanceAutomatedBackup", &[]);
        ok("DescribeDBInstanceAutomatedBackups", &[]);
        ok("SwitchoverReadReplica", &[]);
        ok("DescribeDBRecommendations", &[]);
        ok("ModifyDBRecommendation", &[]);
        ok("DescribeCertificates", &[]);
        ok("ModifyCertificates", &[]);
    }

    #[test]
    fn snapshots_restores_account_events() {
        ok("CopyDBSnapshot", &[("TargetDBSnapshotIdentifier", "s2")]);
        ok(
            "CopyDBParameterGroup",
            &[("TargetDBParameterGroupIdentifier", "p2")],
        );
        ok("DescribeDBParameters", &[]);
        ok("ResetDBParameterGroup", &[("DBParameterGroupName", "p1")]);
        ok("DescribeEngineDefaultParameters", &[]);
        ok("DescribeDBSnapshotAttributes", &[]);
        ok("ModifyDBSnapshot", &[]);
        ok("ModifyDBSnapshotAttribute", &[]);
        ok("RestoreDBClusterFromS3", &[]);
        ok("RestoreDBClusterFromSnapshot", &[]);
        ok("RestoreDBClusterToPointInTime", &[]);
        ok("RestoreDBInstanceFromS3", &[]);
        ok("RestoreDBInstanceToPointInTime", &[]);
        ok("DescribeAccountAttributes", &[]);
        ok("DescribeEventCategories", &[]);
        ok("DescribeEvents", &[]);
        ok("DescribeSourceRegions", &[]);
        ok("DescribeDBLogFiles", &[]);
        ok("DownloadDBLogFilePortion", &[]);
        ok("DescribeDBMajorEngineVersions", &[]);
        ok("DescribeValidDBInstanceModifications", &[]);
        ok("ModifyCurrentDBClusterCapacity", &[]);
        ok("DisableHttpEndpoint", &[]);
        ok("EnableHttpEndpoint", &[]);
    }
}
