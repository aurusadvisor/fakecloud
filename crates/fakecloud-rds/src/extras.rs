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
use std::collections::BTreeMap;

use fakecloud_aws::arn::Arn;
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
    extras: &'a mut BTreeMap<String, BTreeMap<String, Value>>,
    category: &str,
) -> &'a mut BTreeMap<String, Value> {
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
                let arn = Arn::new("rds", region, &aid, &format!("cluster:{id}")).to_string();
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
                let arn = Arn::new("rds", region, &aid, &format!("cluster:{id}")).to_string();
                let mut accounts = write_state!();
                let state = accounts.get_or_create(&aid);
                if let Some(m) = state.extras.get_mut("clusters") { m.remove(&id); }
                Ok(xml_response("DeleteDBCluster", db_cluster_xml(&id, &arn), &rid))
            }
            "ModifyDBCluster" => {
                let id = get_param(req, "DBClusterIdentifier")
                    .ok_or_else(|| missing("DBClusterIdentifier"))?;
                let arn = Arn::new("rds", region, &aid, &format!("cluster:{id}")).to_string();
                let updates: &[(&str, &str)] = &[
                    ("EngineVersion", "EngineVersion"),
                    ("MasterUserPassword", "MasterUserPassword"),
                    ("DBClusterParameterGroupName", "DBClusterParameterGroupName"),
                    ("PreferredBackupWindow", "PreferredBackupWindow"),
                    ("PreferredMaintenanceWindow", "PreferredMaintenanceWindow"),
                    ("BackupRetentionPeriod", "BackupRetentionPeriod"),
                    ("Port", "Port"),
                    ("StorageType", "StorageType"),
                    ("DeletionProtection", "DeletionProtection"),
                    ("EnableIAMDatabaseAuthentication", "IAMDatabaseAuthenticationEnabled"),
                    ("CopyTagsToSnapshot", "CopyTagsToSnapshot"),
                ];
                let mut accounts = write_state!();
                let state = accounts.get_or_create(&aid);
                if let Some(map) = state.extras.get_mut("clusters") {
                    if let Some(entry) = map.get_mut(&id) {
                        if let Some(obj) = entry.as_object_mut() {
                            for (param_name, json_key) in updates {
                                if let Some(v) = get_param(req, param_name) {
                                    obj.insert((*json_key).to_string(), json!(v));
                                }
                            }
                        }
                    }
                }
                Ok(xml_response("ModifyDBCluster", db_cluster_xml(&id, &arn), &rid))
            }
            "StartDBCluster" => {
                let id = get_param(req, "DBClusterIdentifier")
                    .ok_or_else(|| missing("DBClusterIdentifier"))?;
                let arn = Arn::new("rds", region, &aid, &format!("cluster:{id}")).to_string();
                set_cluster_status(self, &aid, &id, "available");
                self.emit_event(
                    RdsSourceType::DbCluster,
                    &id,
                    &arn,
                    "RDS-EVENT-0150",
                    &["notification"],
                    "DB cluster started",
                );
                Ok(xml_response("StartDBCluster", db_cluster_xml(&id, &arn), &rid))
            }
            "StopDBCluster" => {
                let id = get_param(req, "DBClusterIdentifier")
                    .ok_or_else(|| missing("DBClusterIdentifier"))?;
                let arn = Arn::new("rds", region, &aid, &format!("cluster:{id}")).to_string();
                set_cluster_status(self, &aid, &id, "stopped");
                self.emit_event(
                    RdsSourceType::DbCluster,
                    &id,
                    &arn,
                    "RDS-EVENT-0151",
                    &["notification"],
                    "DB cluster stopped",
                );
                Ok(xml_response("StopDBCluster", db_cluster_xml(&id, &arn), &rid))
            }
            "RebootDBCluster" => {
                let id = get_param(req, "DBClusterIdentifier")
                    .ok_or_else(|| missing("DBClusterIdentifier"))?;
                let arn = Arn::new("rds", region, &aid, &format!("cluster:{id}")).to_string();
                set_cluster_status(self, &aid, &id, "available");
                self.emit_event(
                    RdsSourceType::DbCluster,
                    &id,
                    &arn,
                    "RDS-EVENT-0006",
                    &["notification"],
                    "DB cluster reboot",
                );
                Ok(xml_response("RebootDBCluster", db_cluster_xml(&id, &arn), &rid))
            }
            "FailoverDBCluster" => {
                let id = get_param(req, "DBClusterIdentifier")
                    .ok_or_else(|| missing("DBClusterIdentifier"))?;
                let arn = Arn::new("rds", region, &aid, &format!("cluster:{id}")).to_string();
                if let Some(target) = get_param(req, "TargetDBInstanceIdentifier") {
                    let mut accounts = write_state!();
                    let state = accounts.get_or_create(&aid);
                    if let Some(map) = state.extras.get_mut("clusters") {
                        if let Some(entry) = map.get_mut(&id) {
                            if let Some(obj) = entry.as_object_mut() {
                                obj.insert(
                                    "WriterDBInstanceIdentifier".to_string(),
                                    json!(target),
                                );
                            }
                        }
                    }
                }
                self.emit_event(
                    RdsSourceType::DbCluster,
                    &id,
                    &arn,
                    "RDS-EVENT-0072",
                    &["failover"],
                    "DB cluster failover started",
                );
                Ok(xml_response("FailoverDBCluster", db_cluster_xml(&id, &arn), &rid))
            }
            "BacktrackDBCluster" => {
                let id = get_param(req, "DBClusterIdentifier")
                    .ok_or_else(|| missing("DBClusterIdentifier"))?;
                let arn = Arn::new("rds", region, &aid, &format!("cluster:{id}")).to_string();
                if let Some(target) = get_param(req, "BacktrackTo") {
                    let mut accounts = write_state!();
                    let state = accounts.get_or_create(&aid);
                    if let Some(map) = state.extras.get_mut("clusters") {
                        if let Some(entry) = map.get_mut(&id) {
                            if let Some(obj) = entry.as_object_mut() {
                                obj.insert("BacktrackTo".to_string(), json!(target));
                            }
                        }
                    }
                }
                Ok(xml_response("BacktrackDBCluster", db_cluster_xml(&id, &arn), &rid))
            }
            "PromoteReadReplicaDBCluster" => {
                let id = get_param(req, "DBClusterIdentifier")
                    .ok_or_else(|| missing("DBClusterIdentifier"))?;
                let arn = Arn::new("rds", region, &aid, &format!("cluster:{id}")).to_string();
                let mut accounts = write_state!();
                let state = accounts.get_or_create(&aid);
                if let Some(map) = state.extras.get_mut("clusters") {
                    if let Some(entry) = map.get_mut(&id) {
                        if let Some(obj) = entry.as_object_mut() {
                            obj.remove("ReplicationSourceIdentifier");
                        }
                    }
                }
                Ok(xml_response(
                    "PromoteReadReplicaDBCluster",
                    db_cluster_xml(&id, &arn),
                    &rid,
                ))
            }
            "DescribeDBClusters" => {
                let id_filter = get_param(req, "DBClusterIdentifier");
                let accounts = self.state_handle().read();
                let items: Vec<Value> = accounts.get(&aid)
                    .and_then(|s| s.extras.get("clusters"))
                    .map(|m| {
                        m.values()
                            .filter(|v| {
                                id_filter
                                    .as_deref()
                                    .map(|filter| v["DBClusterIdentifier"].as_str() == Some(filter))
                                    .unwrap_or(true)
                            })
                            .cloned()
                            .collect()
                    })
                    .unwrap_or_default();
                let body = items
                    .iter()
                    .map(|v| {
                        format!(
                            "      <DBCluster>\n{}\n      </DBCluster>",
                            db_cluster_member_xml(v)
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n");
                let inner = format!("    <DBClusters>\n{body}\n    </DBClusters>");
                Ok(xml_response("DescribeDBClusters", inner, &rid))
            }

            // ── DB Cluster snapshots ──
            "CreateDBClusterSnapshot" | "CopyDBClusterSnapshot" => {
                let id = get_param(req, "DBClusterSnapshotIdentifier").or_else(|| get_param(req, "TargetDBClusterSnapshotIdentifier"))
                    .ok_or_else(|| missing("DBClusterSnapshotIdentifier"))?;
                let arn = Arn::new("rds", region, &aid, &format!("cluster-snapshot:{id}")).to_string();
                let cluster = get_param(req, "DBClusterIdentifier").unwrap_or_else(|| "default".to_string());
                let entry = json!({"DBClusterSnapshotIdentifier": id, "DBClusterSnapshotArn": arn, "DBClusterIdentifier": cluster, "Status": "available"});
                let mut accounts = write_state!();
                let state = accounts.get_or_create(&aid);
                store(&mut state.extras, "cluster_snapshots").insert(id.clone(), entry);
                Ok(xml_response(action.as_str(), cluster_snapshot_xml(&id, &arn, &cluster), &rid))
            }
            "DeleteDBClusterSnapshot" => {
                let id = get_param(req, "DBClusterSnapshotIdentifier").ok_or_else(|| missing("DBClusterSnapshotIdentifier"))?;
                let arn = Arn::new("rds", region, &aid, &format!("cluster-snapshot:{id}")).to_string();
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
                let arn = Arn::new("rds", region, &aid, &format!("cluster-pg:{name}")).to_string();
                let family = get_param(req, "DBParameterGroupFamily").unwrap_or_else(|| "aurora-postgresql15".to_string());
                let entry = json!({"DBClusterParameterGroupName": name, "DBClusterParameterGroupArn": arn, "DBParameterGroupFamily": family, "Description": get_param(req, "Description").unwrap_or_default()});
                let mut accounts = write_state!();
                let state = accounts.get_or_create(&aid);
                store(&mut state.extras, "cluster_param_groups").insert(name.clone(), entry);
                Ok(xml_response(action.as_str(), cluster_pg_xml(&name, &arn, &family), &rid))
            }
            "ModifyDBClusterParameterGroup" => {
                let name = get_param(req, "DBClusterParameterGroupName").ok_or_else(|| missing("DBClusterParameterGroupName"))?;
                let parsed = crate::service::parse_db_parameter_members(req);
                let mut accounts = write_state!();
                let state = accounts.get_or_create(&aid);
                if let Some(map) = state.extras.get_mut("cluster_param_groups") {
                    if let Some(entry) = map.get_mut(&name) {
                        if let Some(obj) = entry.as_object_mut() {
                            if !obj.contains_key("Parameters") {
                                obj.insert("Parameters".to_string(), json!({}));
                            }
                            if let Some(p) = obj.get_mut("Parameters").and_then(|p| p.as_object_mut()) {
                                for (n, v) in parsed {
                                    p.insert(n, json!(v));
                                }
                            }
                        }
                    }
                }
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
            "DescribeDBClusterParameters" => {
                let name = get_param(req, "DBClusterParameterGroupName").ok_or_else(|| missing("DBClusterParameterGroupName"))?;
                let source_filter = get_param(req, "Source");
                let want_user_source = source_filter.as_deref().is_none_or(|s| s == "user");
                let accounts = self.state_handle().read();
                let state = accounts.get(&aid);
                let mut members = String::new();
                if want_user_source {
                    if let Some(s) = state {
                        if let Some(map) = s.extras.get("cluster_param_groups") {
                            if let Some(entry) = map.get(&name) {
                                if let Some(params) = entry.get("Parameters").and_then(|p| p.as_object()) {
                                    for (n, v) in params {
                                        let value = v.as_str().unwrap_or("").to_string();
                                        members.push_str(&format!(
                                            "      <Parameter>\n        <ParameterName>{}</ParameterName>\n        <ParameterValue>{}</ParameterValue>\n        <Source>user</Source>\n        <ApplyType>dynamic</ApplyType>\n        <DataType>string</DataType>\n        <IsModifiable>true</IsModifiable>\n      </Parameter>\n",
                                            xml_escape(n),
                                            xml_escape(&value),
                                        ));
                                    }
                                }
                            }
                        }
                    }
                }
                Ok(xml_response("DescribeDBClusterParameters", format!("    <Parameters>\n{members}    </Parameters>"), &rid))
            }
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
                let arn = Arn::new("rds", region, &aid, &format!("db-proxy:{name}")).to_string();
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
                let arn = Arn::new("rds", region, &aid, &format!("og:{name}")).to_string();
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
                let arn = Arn::global("rds", &aid, &format!("global-cluster:{id}")).to_string();
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
                let arn = Arn::new("rds", region, &aid, &format!("integration:{name}")).to_string();
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
            "PromoteReadReplica" => promote_read_replica_action(self, &aid, req, &rid),
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
                                Arn::new("rds", region, &aid, &format!("db:{id}")).to_string()
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
            "RestoreDBClusterFromSnapshot" => {
                let target = get_param(req, "DBClusterIdentifier")
                    .ok_or_else(|| missing("DBClusterIdentifier"))?;
                let snapshot_id = get_param(req, "SnapshotIdentifier")
                    .or_else(|| get_param(req, "DBClusterSnapshotIdentifier"))
                    .ok_or_else(|| missing("SnapshotIdentifier"))?;
                let arn = Arn::new("rds", region, &aid, &format!("cluster:{target}")).to_string();
                let mut accounts = write_state!();
                let state = accounts.get_or_create(&aid);
                let snapshot = state
                    .extras
                    .get("cluster_snapshots")
                    .and_then(|m| m.get(&snapshot_id))
                    .cloned()
                    .ok_or_else(|| {
                        AwsServiceError::aws_error(
                            StatusCode::NOT_FOUND,
                            "DBClusterSnapshotNotFoundFault",
                            format!("DBClusterSnapshot {snapshot_id} not found."),
                        )
                    })?;
                let source_cluster_id = snapshot
                    .get("DBClusterIdentifier")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let mut entry = state
                    .extras
                    .get("clusters")
                    .and_then(|m| m.get(source_cluster_id))
                    .cloned()
                    .unwrap_or_else(|| {
                        json!({
                            "Engine": get_param(req, "Engine").unwrap_or_else(|| "aurora-postgresql".to_string()),
                            "EngineVersion": get_param(req, "EngineVersion").unwrap_or_else(|| "15.3".to_string()),
                            "MasterUsername": "postgres",
                            "Port": 5432,
                        })
                    });
                if let Some(obj) = entry.as_object_mut() {
                    obj.insert("DBClusterIdentifier".to_string(), json!(target));
                    obj.insert("DBClusterArn".to_string(), json!(arn));
                    obj.insert("Status".to_string(), json!("available"));
                    obj.insert(
                        "Endpoint".to_string(),
                        json!(format!("{target}.cluster-xxx.{region}.rds.amazonaws.com")),
                    );
                    obj.insert(
                        "ReaderEndpoint".to_string(),
                        json!(format!("{target}.cluster-ro-xxx.{region}.rds.amazonaws.com")),
                    );
                    obj.remove("ReplicationSourceIdentifier");
                    if let Some(engine) = get_param(req, "Engine") {
                        obj.insert("Engine".to_string(), json!(engine));
                    }
                    if let Some(version) = get_param(req, "EngineVersion") {
                        obj.insert("EngineVersion".to_string(), json!(version));
                    }
                    if let Some(port) = get_param(req, "Port").and_then(|p| p.parse::<i64>().ok()) {
                        obj.insert("Port".to_string(), json!(port));
                    }
                }
                store(&mut state.extras, "clusters").insert(target.clone(), entry);
                drop(accounts);
                self.emit_event(
                    RdsSourceType::DbCluster,
                    &target,
                    &arn,
                    "RDS-EVENT-0170",
                    &["creation"],
                    "DB cluster restored from snapshot",
                );
                Ok(xml_response(
                    "RestoreDBClusterFromSnapshot",
                    db_cluster_xml(&target, &arn),
                    &rid,
                ))
            }
            "RestoreDBClusterToPointInTime" => {
                let target = get_param(req, "DBClusterIdentifier")
                    .ok_or_else(|| missing("DBClusterIdentifier"))?;
                let source = get_param(req, "SourceDBClusterIdentifier")
                    .ok_or_else(|| missing("SourceDBClusterIdentifier"))?;
                let arn = Arn::new("rds", region, &aid, &format!("cluster:{target}")).to_string();
                let mut accounts = write_state!();
                let state = accounts.get_or_create(&aid);
                let mut entry = state
                    .extras
                    .get("clusters")
                    .and_then(|m| m.get(&source))
                    .cloned()
                    .ok_or_else(|| {
                        AwsServiceError::aws_error(
                            StatusCode::NOT_FOUND,
                            "DBClusterNotFoundFault",
                            format!("DBCluster {source} not found."),
                        )
                    })?;
                if let Some(obj) = entry.as_object_mut() {
                    obj.insert("DBClusterIdentifier".to_string(), json!(target));
                    obj.insert("DBClusterArn".to_string(), json!(arn));
                    obj.insert("Status".to_string(), json!("available"));
                    obj.insert(
                        "Endpoint".to_string(),
                        json!(format!("{target}.cluster-xxx.{region}.rds.amazonaws.com")),
                    );
                    obj.insert(
                        "ReaderEndpoint".to_string(),
                        json!(format!("{target}.cluster-ro-xxx.{region}.rds.amazonaws.com")),
                    );
                    if let Some(restore_time) = get_param(req, "RestoreToTime") {
                        obj.insert("RestoreToTime".to_string(), json!(restore_time));
                    }
                    if let Some(latest) = get_param(req, "UseLatestRestorableTime") {
                        obj.insert("UseLatestRestorableTime".to_string(), json!(latest));
                    }
                }
                store(&mut state.extras, "clusters").insert(target.clone(), entry);
                drop(accounts);
                self.emit_event(
                    RdsSourceType::DbCluster,
                    &target,
                    &arn,
                    "RDS-EVENT-0171",
                    &["creation"],
                    "DB cluster restored to point in time",
                );
                Ok(xml_response(
                    "RestoreDBClusterToPointInTime",
                    db_cluster_xml(&target, &arn),
                    &rid,
                ))
            }
            "RestoreDBClusterFromS3" => Ok(xml_response(
                action.as_str(),
                "    <DBCluster/>".to_string(),
                &rid,
            )),

            // ── Recommendations ──
            "DescribeDBRecommendations" => Ok(xml_response("DescribeDBRecommendations", "    <DBRecommendations/>".to_string(), &rid)),
            "ModifyDBRecommendation" => Ok(xml_response("ModifyDBRecommendation", "    <DBRecommendation/>".to_string(), &rid)),

            // ── Certificates ──
            "DescribeCertificates" => Ok(xml_response("DescribeCertificates", "    <Certificates/>".to_string(), &rid)),
            "ModifyCertificates" => Ok(xml_response("ModifyCertificates", "    <Certificate/>".to_string(), &rid)),

            // ── Account / events / regions / log files / capacity ──
            "DescribeAccountAttributes" => Ok(xml_response("DescribeAccountAttributes", "    <AccountQuotas/>".to_string(), &rid)),
            "DescribeEventCategories" => Ok(xml_response("DescribeEventCategories", "    <EventCategoriesMapList/>".to_string(), &rid)),
            "DescribeEvents" => self.describe_events(req, &rid),
            "DescribeSourceRegions" => Ok(xml_response("DescribeSourceRegions", "    <SourceRegions/>".to_string(), &rid)),
            "DescribeDBLogFiles" => Ok(xml_response("DescribeDBLogFiles", "    <DescribeDBLogFiles/>".to_string(), &rid)),
            "DownloadDBLogFilePortion" => Ok(xml_response("DownloadDBLogFilePortion", "    <LogFileData></LogFileData>\n    <Marker>0</Marker>\n    <AdditionalDataPending>false</AdditionalDataPending>".to_string(), &rid)),
            "DescribeDBMajorEngineVersions" => Ok(xml_response("DescribeDBMajorEngineVersions", "    <DBMajorEngineVersions/>".to_string(), &rid)),
            "DescribeValidDBInstanceModifications" => Ok(xml_response("DescribeValidDBInstanceModifications", "    <ValidDBInstanceModificationsMessage>\n      <ValidProcessorFeatures/>\n      <Storage/>\n    </ValidDBInstanceModificationsMessage>".to_string(), &rid)),
            "ModifyCurrentDBClusterCapacity" => Ok(xml_response("ModifyCurrentDBClusterCapacity", "    <DBClusterIdentifier>x</DBClusterIdentifier>\n    <CurrentCapacity>4</CurrentCapacity>".to_string(), &rid)),
            "DisableHttpEndpoint" => Ok(xml_response("DisableHttpEndpoint", "    <HttpEndpointEnabled>false</HttpEndpointEnabled>".to_string(), &rid)),
            "EnableHttpEndpoint" => Ok(xml_response("EnableHttpEndpoint", "    <HttpEndpointEnabled>true</HttpEndpointEnabled>".to_string(), &rid)),

            // ── Read replicas ──
            "SwitchoverReadReplica" => promote_read_replica_action(self, &aid, req, &rid),

            _ => Err(AwsServiceError::action_not_implemented("rds", &action)),
        }
    }
}

/// Update the `Status` field on the stored cluster JSON entry. Silent
/// no-op when the cluster doesn't exist (caller already returned a
/// stub response so this can't fail without changing the contract).
fn set_cluster_status(svc: &RdsService, account_id: &str, cluster_id: &str, status: &str) {
    let mut accounts = svc.state_handle().write();
    let state = accounts.get_or_create(account_id);
    if let Some(map) = state.extras.get_mut("clusters") {
        if let Some(entry) = map.get_mut(cluster_id) {
            if let Some(obj) = entry.as_object_mut() {
                obj.insert("Status".to_string(), json!(status));
            }
        }
    }
}

/// PromoteReadReplica + SwitchoverReadReplica share the same shape:
/// resolve the named instance, ensure it's actually a replica, clear
/// the source pointer, optionally update backup config, and trim the
/// instance from its source's replica list. AWS distinguishes the two
/// (Switchover keeps the source as a new replica of the new primary
/// while Promote standalone-promotes), but both produce a promoted
/// replica with no upstream — we model the standalone path for both.
fn promote_read_replica_action(
    svc: &RdsService,
    account_id: &str,
    req: &AwsRequest,
    rid: &str,
) -> Result<AwsResponse, AwsServiceError> {
    let id =
        get_param(req, "DBInstanceIdentifier").ok_or_else(|| missing("DBInstanceIdentifier"))?;
    let backup_retention =
        get_param(req, "BackupRetentionPeriod").and_then(|v| v.parse::<i32>().ok());
    let preferred_window = get_param(req, "PreferredBackupWindow");

    let mut accounts = svc.state_handle().write();
    let state = accounts.get_or_create(account_id);
    let source_id = state
        .instances
        .get(&id)
        .and_then(|i| i.read_replica_source_db_instance_identifier.clone());
    let instance = state.instances.get_mut(&id).ok_or_else(|| {
        AwsServiceError::aws_error(
            StatusCode::NOT_FOUND,
            "DBInstanceNotFound",
            format!("DBInstance {id} not found."),
        )
    })?;
    if instance
        .read_replica_source_db_instance_identifier
        .is_none()
    {
        return Err(AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "InvalidDBInstanceState",
            format!("DB instance {id} is not a read replica."),
        ));
    }
    instance.read_replica_source_db_instance_identifier = None;
    if let Some(retention) = backup_retention {
        instance.backup_retention_period = retention;
    }
    if let Some(window) = preferred_window {
        instance.preferred_backup_window = window;
    }
    let xml = crate::service::db_instance_xml(instance, Some("modifying"));
    if let Some(source_id) = source_id {
        if let Some(src) = state.instances.get_mut(&source_id) {
            src.read_replica_db_instance_identifiers
                .retain(|r| r != &id);
        }
    }
    drop(accounts);
    Ok(xml_response(
        "PromoteReadReplica",
        format!("    <DBInstance>\n{xml}    </DBInstance>"),
        rid,
    ))
}

// ── XML helpers per resource ──

fn db_cluster_xml(id: &str, arn: &str) -> String {
    format!(
        "    <DBCluster>\n      <DBClusterIdentifier>{}</DBClusterIdentifier>\n      <DBClusterArn>{}</DBClusterArn>\n      <Status>available</Status>\n    </DBCluster>",
        xml_escape(id), xml_escape(arn)
    )
}

fn db_cluster_member_xml(v: &Value) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "          <DBClusterIdentifier>{}</DBClusterIdentifier>\n",
        xml_escape(v["DBClusterIdentifier"].as_str().unwrap_or(""))
    ));
    out.push_str(&format!(
        "          <DBClusterArn>{}</DBClusterArn>\n",
        xml_escape(v["DBClusterArn"].as_str().unwrap_or(""))
    ));
    out.push_str(&format!(
        "          <Status>{}</Status>\n",
        xml_escape(v["Status"].as_str().unwrap_or("available"))
    ));
    if let Some(s) = v["Engine"].as_str() {
        out.push_str(&format!("          <Engine>{}</Engine>\n", xml_escape(s)));
    }
    if let Some(s) = v["EngineVersion"].as_str() {
        out.push_str(&format!(
            "          <EngineVersion>{}</EngineVersion>\n",
            xml_escape(s)
        ));
    }
    if let Some(s) = v["MasterUsername"].as_str() {
        out.push_str(&format!(
            "          <MasterUsername>{}</MasterUsername>\n",
            xml_escape(s)
        ));
    }
    if let Some(s) = v["DatabaseName"].as_str() {
        out.push_str(&format!(
            "          <DatabaseName>{}</DatabaseName>\n",
            xml_escape(s)
        ));
    }
    if let Some(s) = v["Endpoint"].as_str() {
        out.push_str(&format!(
            "          <Endpoint>{}</Endpoint>\n",
            xml_escape(s)
        ));
    }
    if let Some(s) = v["ReaderEndpoint"].as_str() {
        out.push_str(&format!(
            "          <ReaderEndpoint>{}</ReaderEndpoint>\n",
            xml_escape(s)
        ));
    }
    if let Some(n) = v["Port"].as_i64() {
        out.push_str(&format!("          <Port>{}</Port>\n", n));
    }
    if let Some(n) = v["AllocatedStorage"].as_i64() {
        out.push_str(&format!(
            "          <AllocatedStorage>{}</AllocatedStorage>\n",
            n
        ));
    }
    if let Some(n) = v["BackupRetentionPeriod"].as_i64() {
        out.push_str(&format!(
            "          <BackupRetentionPeriod>{}</BackupRetentionPeriod>\n",
            n
        ));
    }
    if let Some(b) = v["StorageEncrypted"].as_bool() {
        out.push_str(&format!(
            "          <StorageEncrypted>{}</StorageEncrypted>\n",
            b
        ));
    }
    if let Some(s) = v["KmsKeyId"].as_str() {
        out.push_str(&format!(
            "          <KmsKeyId>{}</KmsKeyId>\n",
            xml_escape(s)
        ));
    }
    if let Some(b) = v["DeletionProtection"].as_bool() {
        out.push_str(&format!(
            "          <DeletionProtection>{}</DeletionProtection>\n",
            b
        ));
    }
    if let Some(s) = v["DBSubnetGroup"].as_str() {
        out.push_str(&format!(
            "          <DBSubnetGroup>{}</DBSubnetGroup>\n",
            xml_escape(s)
        ));
    }
    if let Some(s) = v["DbClusterResourceId"].as_str() {
        out.push_str(&format!(
            "          <DbClusterResourceId>{}</DbClusterResourceId>\n",
            xml_escape(s)
        ));
    }
    if let Some(s) = v["ClusterCreateTime"].as_str() {
        out.push_str(&format!(
            "          <ClusterCreateTime>{}</ClusterCreateTime>\n",
            xml_escape(s)
        ));
    }
    out
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

impl RdsService {
    /// Real DescribeEvents implementation: read the per-account events
    /// ring written to by `emit_event`. Honour SourceType /
    /// SourceIdentifier / Duration / StartTime / EndTime / EventCategories
    /// filters and emit them as the DescribeEventsResult shape.
    pub(crate) fn describe_events(
        &self,
        req: &AwsRequest,
        rid: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let source_type = get_param(req, "SourceType");
        let source_identifier = get_param(req, "SourceIdentifier");
        let event_categories: Vec<String> = (1..=20)
            .filter_map(|i| get_param(req, &format!("EventCategories.member.{i}")))
            .collect();
        let duration_minutes: i64 = get_param(req, "Duration")
            .and_then(|s| s.parse().ok())
            .unwrap_or(60);
        let now = chrono::Utc::now();
        let start_time = get_param(req, "StartTime")
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok())
            .map(|dt| dt.with_timezone(&chrono::Utc))
            .unwrap_or_else(|| now - chrono::Duration::minutes(duration_minutes));
        let end_time = get_param(req, "EndTime")
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok())
            .map(|dt| dt.with_timezone(&chrono::Utc))
            .unwrap_or(now);

        let state = self.state_handle().read();
        let events = state
            .get(&req.account_id)
            .map(|s| s.events.clone())
            .unwrap_or_default();
        drop(state);

        let mut body = String::from("    <Events>\n");
        for e in events.iter().filter(|e| {
            source_type.as_deref().is_none_or(|t| e.source_type == t)
                && source_identifier
                    .as_deref()
                    .is_none_or(|i| e.source_identifier == i)
                && (event_categories.is_empty()
                    || event_categories
                        .iter()
                        .any(|c| e.event_categories.iter().any(|ec| ec == c)))
                && e.date >= start_time
                && e.date <= end_time
        }) {
            body.push_str("      <Event>\n");
            body.push_str(&format!(
                "        <SourceIdentifier>{}</SourceIdentifier>\n",
                xml_escape(&e.source_identifier),
            ));
            body.push_str(&format!(
                "        <SourceType>{}</SourceType>\n",
                xml_escape(&e.source_type),
            ));
            body.push_str(&format!(
                "        <Message>{}</Message>\n",
                xml_escape(&e.message),
            ));
            body.push_str(&format!(
                "        <SourceArn>{}</SourceArn>\n",
                xml_escape(&e.source_arn),
            ));
            body.push_str("        <EventCategories>\n");
            for cat in &e.event_categories {
                body.push_str(&format!(
                    "          <EventCategory>{}</EventCategory>\n",
                    xml_escape(cat),
                ));
            }
            body.push_str("        </EventCategories>\n");
            body.push_str(&format!("        <Date>{}</Date>\n", e.date.to_rfc3339(),));
            body.push_str("      </Event>\n");
        }
        body.push_str("    </Events>");
        Ok(xml_response("DescribeEvents", body, rid))
    }
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
    use serde_json::json;
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
    fn describe_events_returns_emitted_events() {
        let svc = svc();
        // Push two events directly into state.
        {
            let state = svc.state_handle();
            let mut accounts = state.write();
            let s = accounts.get_or_create("000000000000");
            s.push_event(crate::state::RdsEventRecord {
                source_identifier: "instance-a".to_string(),
                source_type: "db-instance".to_string(),
                source_arn: "arn:aws:rds:us-east-1:000000000000:db:instance-a".to_string(),
                event_id: "RDS-EVENT-0001".to_string(),
                event_categories: vec!["creation".to_string()],
                message: "DB instance created".to_string(),
                date: chrono::Utc::now(),
            });
            s.push_event(crate::state::RdsEventRecord {
                source_identifier: "instance-b".to_string(),
                source_type: "db-instance".to_string(),
                source_arn: "arn:aws:rds:us-east-1:000000000000:db:instance-b".to_string(),
                event_id: "RDS-EVENT-0002".to_string(),
                event_categories: vec!["failure".to_string()],
                message: "DB instance failed".to_string(),
                date: chrono::Utc::now(),
            });
        }
        let resp = svc
            .handle_extra_action(&req("DescribeEvents", &[]))
            .unwrap();
        let body = String::from_utf8(resp.body.expect_bytes().to_vec()).unwrap();
        assert!(body.contains("instance-a"), "missing instance-a in {body}");
        assert!(body.contains("instance-b"), "missing instance-b in {body}");
        assert!(body.contains("DB instance created"));
    }

    #[test]
    fn describe_events_filters_by_source_identifier() {
        let svc = svc();
        {
            let state = svc.state_handle();
            let mut accounts = state.write();
            let s = accounts.get_or_create("000000000000");
            for id in ["i-a", "i-b", "i-c"] {
                s.push_event(crate::state::RdsEventRecord {
                    source_identifier: id.to_string(),
                    source_type: "db-instance".to_string(),
                    source_arn: format!("arn:aws:rds:us-east-1:000000000000:db:{id}"),
                    event_id: "RDS-EVENT-0001".to_string(),
                    event_categories: vec!["creation".to_string()],
                    message: format!("created {id}"),
                    date: chrono::Utc::now(),
                });
            }
        }
        let resp = svc
            .handle_extra_action(&req("DescribeEvents", &[("SourceIdentifier", "i-b")]))
            .unwrap();
        let body = String::from_utf8(resp.body.expect_bytes().to_vec()).unwrap();
        assert!(body.contains("created i-b"));
        assert!(!body.contains("created i-a"));
        assert!(!body.contains("created i-c"));
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
        ok(
            "DescribeDBClusterParameters",
            &[("DBClusterParameterGroupName", "cpg")],
        );
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
        // PromoteReadReplica + SwitchoverReadReplica need a real
        // replica instance; covered by the dedicated tests below.
        ok("StartDBInstance", &[]);
        ok("StopDBInstance", &[]);
        ok("StartDBInstanceAutomatedBackupsReplication", &[]);
        ok("StopDBInstanceAutomatedBackupsReplication", &[]);
        ok("DeleteDBInstanceAutomatedBackup", &[]);
        ok("DescribeDBInstanceAutomatedBackups", &[]);
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

    fn seed_replica(svc: &RdsService, replica_id: &str, source_id: &str) {
        use crate::state::DbInstance;
        use chrono::Utc;
        let now = Utc::now();
        let mut accounts = svc.state_handle().write();
        let state = accounts.get_or_create("000000000000");
        let arn = state.db_instance_arn(replica_id);
        let source_arn = state.db_instance_arn(source_id);
        // Source first.
        state.instances.insert(
            source_id.to_string(),
            DbInstance {
                db_instance_identifier: source_id.to_string(),
                db_instance_arn: source_arn,
                db_instance_class: "db.t3.micro".to_string(),
                engine: "postgres".to_string(),
                engine_version: "16.3".to_string(),
                db_instance_status: "available".to_string(),
                master_username: "admin".to_string(),
                db_name: None,
                endpoint_address: "127.0.0.1".to_string(),
                port: 5432,
                allocated_storage: 20,
                publicly_accessible: false,
                deletion_protection: false,
                created_at: now,
                dbi_resource_id: format!("db-{}", uuid::Uuid::new_v4().simple()),
                master_user_password: "".to_string(),
                container_id: String::new(),
                host_port: 0,
                tags: Vec::new(),
                read_replica_source_db_instance_identifier: None,
                read_replica_db_instance_identifiers: vec![replica_id.to_string()],
                vpc_security_group_ids: Vec::new(),
                db_parameter_group_name: None,
                backup_retention_period: 1,
                preferred_backup_window: "03:00-04:00".to_string(),
                preferred_maintenance_window: None,
                latest_restorable_time: Some(now),
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
            },
        );
        // Replica points at source.
        state.instances.insert(
            replica_id.to_string(),
            DbInstance {
                db_instance_identifier: replica_id.to_string(),
                db_instance_arn: arn,
                db_instance_class: "db.t3.micro".to_string(),
                engine: "postgres".to_string(),
                engine_version: "16.3".to_string(),
                db_instance_status: "available".to_string(),
                master_username: "admin".to_string(),
                db_name: None,
                endpoint_address: "127.0.0.1".to_string(),
                port: 5432,
                allocated_storage: 20,
                publicly_accessible: false,
                deletion_protection: false,
                created_at: now,
                dbi_resource_id: format!("db-{}", uuid::Uuid::new_v4().simple()),
                master_user_password: "".to_string(),
                container_id: String::new(),
                host_port: 0,
                tags: Vec::new(),
                read_replica_source_db_instance_identifier: Some(source_id.to_string()),
                read_replica_db_instance_identifiers: Vec::new(),
                vpc_security_group_ids: Vec::new(),
                db_parameter_group_name: None,
                backup_retention_period: 1,
                preferred_backup_window: "03:00-04:00".to_string(),
                preferred_maintenance_window: None,
                latest_restorable_time: Some(now),
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
            },
        );
    }

    #[test]
    fn promote_read_replica_clears_source_pointer_and_trims_source_list() {
        let svc = svc();
        seed_replica(&svc, "replica-1", "source-1");
        let resp = svc
            .handle_extra_action(&req(
                "PromoteReadReplica",
                &[
                    ("DBInstanceIdentifier", "replica-1"),
                    ("BackupRetentionPeriod", "7"),
                    ("PreferredBackupWindow", "04:00-05:00"),
                ],
            ))
            .expect("PromoteReadReplica");
        assert!(resp.status.is_success());
        let body = String::from_utf8(resp.body.expect_bytes().to_vec()).unwrap();
        assert!(body.contains("<DBInstanceIdentifier>replica-1</DBInstanceIdentifier>"));

        let accounts = svc.state_handle().read();
        let state = accounts.get("000000000000").unwrap();
        let replica = state.instances.get("replica-1").unwrap();
        assert!(replica.read_replica_source_db_instance_identifier.is_none());
        assert_eq!(replica.backup_retention_period, 7);
        assert_eq!(replica.preferred_backup_window, "04:00-05:00");
        let source = state.instances.get("source-1").unwrap();
        assert!(source.read_replica_db_instance_identifiers.is_empty());
    }

    #[test]
    fn promote_read_replica_rejects_non_replica() {
        let svc = svc();
        seed_replica(&svc, "replica-1", "source-1");
        let err = svc
            .handle_extra_action(&req(
                "PromoteReadReplica",
                &[("DBInstanceIdentifier", "source-1")],
            ))
            .err()
            .expect("non-replica should be rejected");
        assert_eq!(err.code(), "InvalidDBInstanceState");
    }

    #[test]
    fn switchover_read_replica_uses_promote_path() {
        let svc = svc();
        seed_replica(&svc, "replica-1", "source-1");
        svc.handle_extra_action(&req(
            "SwitchoverReadReplica",
            &[("DBInstanceIdentifier", "replica-1")],
        ))
        .expect("SwitchoverReadReplica");
        let accounts = svc.state_handle().read();
        let replica = accounts
            .get("000000000000")
            .unwrap()
            .instances
            .get("replica-1")
            .unwrap();
        assert!(replica.read_replica_source_db_instance_identifier.is_none());
    }

    #[test]
    fn promote_read_replica_unknown_instance_returns_not_found() {
        let svc = svc();
        let err = svc
            .handle_extra_action(&req(
                "PromoteReadReplica",
                &[("DBInstanceIdentifier", "ghost")],
            ))
            .err()
            .expect("unknown instance should be rejected");
        assert_eq!(err.code(), "DBInstanceNotFound");
    }

    fn cluster_value(svc: &RdsService, id: &str) -> serde_json::Value {
        let accounts = svc.state_handle().read();
        accounts
            .get("000000000000")
            .and_then(|s| s.extras.get("clusters"))
            .and_then(|m| m.get(id))
            .cloned()
            .expect("cluster present")
    }

    fn create_cluster(svc: &RdsService, id: &str) {
        svc.handle_extra_action(&req("CreateDBCluster", &[("DBClusterIdentifier", id)]))
            .expect("CreateDBCluster");
    }

    #[test]
    fn modify_db_cluster_persists_fields() {
        let svc = svc();
        create_cluster(&svc, "c1");
        svc.handle_extra_action(&req(
            "ModifyDBCluster",
            &[
                ("DBClusterIdentifier", "c1"),
                ("EngineVersion", "16.4"),
                ("BackupRetentionPeriod", "14"),
                ("PreferredBackupWindow", "01:00-02:00"),
                ("PreferredMaintenanceWindow", "sun:03:00-sun:04:00"),
                ("Port", "5433"),
                ("DeletionProtection", "true"),
                ("EnableIAMDatabaseAuthentication", "true"),
                ("CopyTagsToSnapshot", "true"),
                ("DBClusterParameterGroupName", "custom-pg"),
            ],
        ))
        .expect("ModifyDBCluster");
        let v = cluster_value(&svc, "c1");
        assert_eq!(v["EngineVersion"].as_str(), Some("16.4"));
        assert_eq!(v["BackupRetentionPeriod"].as_str(), Some("14"));
        assert_eq!(v["PreferredBackupWindow"].as_str(), Some("01:00-02:00"));
        assert_eq!(
            v["PreferredMaintenanceWindow"].as_str(),
            Some("sun:03:00-sun:04:00")
        );
        assert_eq!(v["Port"].as_str(), Some("5433"));
        assert_eq!(v["DeletionProtection"].as_str(), Some("true"));
        assert_eq!(v["IAMDatabaseAuthenticationEnabled"].as_str(), Some("true"));
        assert_eq!(v["CopyTagsToSnapshot"].as_str(), Some("true"));
        assert_eq!(v["DBClusterParameterGroupName"].as_str(), Some("custom-pg"));
    }

    #[test]
    fn start_db_cluster_sets_status_available() {
        let svc = svc();
        create_cluster(&svc, "c1");
        svc.handle_extra_action(&req("StopDBCluster", &[("DBClusterIdentifier", "c1")]))
            .expect("StopDBCluster");
        assert_eq!(
            cluster_value(&svc, "c1")["Status"].as_str(),
            Some("stopped")
        );
        svc.handle_extra_action(&req("StartDBCluster", &[("DBClusterIdentifier", "c1")]))
            .expect("StartDBCluster");
        assert_eq!(
            cluster_value(&svc, "c1")["Status"].as_str(),
            Some("available")
        );
    }

    #[test]
    fn reboot_db_cluster_sets_status_available() {
        let svc = svc();
        create_cluster(&svc, "c1");
        svc.handle_extra_action(&req("RebootDBCluster", &[("DBClusterIdentifier", "c1")]))
            .expect("RebootDBCluster");
        assert_eq!(
            cluster_value(&svc, "c1")["Status"].as_str(),
            Some("available")
        );
    }

    #[test]
    fn failover_db_cluster_records_target_writer() {
        let svc = svc();
        create_cluster(&svc, "c1");
        svc.handle_extra_action(&req(
            "FailoverDBCluster",
            &[
                ("DBClusterIdentifier", "c1"),
                ("TargetDBInstanceIdentifier", "writer-2"),
            ],
        ))
        .expect("FailoverDBCluster");
        assert_eq!(
            cluster_value(&svc, "c1")["WriterDBInstanceIdentifier"].as_str(),
            Some("writer-2")
        );
    }

    #[test]
    fn backtrack_db_cluster_records_target() {
        let svc = svc();
        create_cluster(&svc, "c1");
        svc.handle_extra_action(&req(
            "BacktrackDBCluster",
            &[
                ("DBClusterIdentifier", "c1"),
                ("BacktrackTo", "2026-05-01T00:00:00Z"),
            ],
        ))
        .expect("BacktrackDBCluster");
        assert_eq!(
            cluster_value(&svc, "c1")["BacktrackTo"].as_str(),
            Some("2026-05-01T00:00:00Z")
        );
    }

    #[test]
    fn promote_read_replica_db_cluster_clears_source() {
        let svc = svc();
        create_cluster(&svc, "c1");
        // Seed cluster as a replica.
        {
            let mut accounts = svc.state_handle().write();
            let state = accounts.get_or_create("000000000000");
            if let Some(map) = state.extras.get_mut("clusters") {
                if let Some(entry) = map.get_mut("c1") {
                    if let Some(obj) = entry.as_object_mut() {
                        obj.insert(
                            "ReplicationSourceIdentifier".to_string(),
                            json!("arn:aws:rds:us-east-1:000000000000:cluster:source"),
                        );
                    }
                }
            }
        }
        svc.handle_extra_action(&req(
            "PromoteReadReplicaDBCluster",
            &[("DBClusterIdentifier", "c1")],
        ))
        .expect("PromoteReadReplicaDBCluster");
        assert!(cluster_value(&svc, "c1")
            .get("ReplicationSourceIdentifier")
            .is_none());
    }

    #[test]
    fn cluster_lifecycle_op_missing_identifier_errors() {
        let svc = svc();
        let err = svc
            .handle_extra_action(&req("ModifyDBCluster", &[]))
            .err()
            .expect("missing identifier should error");
        assert_eq!(err.code(), "InvalidParameterValue");
    }

    #[test]
    fn restore_db_cluster_from_snapshot_clones_source_cluster_fields() {
        let svc = svc();
        create_cluster(&svc, "src");
        // Mutate source so we can verify it carries through.
        svc.handle_extra_action(&req(
            "ModifyDBCluster",
            &[
                ("DBClusterIdentifier", "src"),
                ("EngineVersion", "16.1"),
                ("BackupRetentionPeriod", "21"),
            ],
        ))
        .expect("ModifyDBCluster");
        // Snapshot the source.
        svc.handle_extra_action(&req(
            "CreateDBClusterSnapshot",
            &[
                ("DBClusterSnapshotIdentifier", "snap1"),
                ("DBClusterIdentifier", "src"),
            ],
        ))
        .expect("CreateDBClusterSnapshot");
        svc.handle_extra_action(&req(
            "RestoreDBClusterFromSnapshot",
            &[
                ("DBClusterIdentifier", "restored"),
                ("SnapshotIdentifier", "snap1"),
            ],
        ))
        .expect("RestoreDBClusterFromSnapshot");
        let v = cluster_value(&svc, "restored");
        assert_eq!(v["DBClusterIdentifier"].as_str(), Some("restored"));
        assert_eq!(v["EngineVersion"].as_str(), Some("16.1"));
        assert_eq!(v["BackupRetentionPeriod"].as_str(), Some("21"));
        assert_eq!(v["Status"].as_str(), Some("available"));
        assert!(v["DBClusterArn"]
            .as_str()
            .unwrap_or_default()
            .ends_with(":cluster:restored"));
    }

    #[test]
    fn restore_db_cluster_from_snapshot_unknown_snapshot_errors() {
        let svc = svc();
        let err = svc
            .handle_extra_action(&req(
                "RestoreDBClusterFromSnapshot",
                &[
                    ("DBClusterIdentifier", "restored"),
                    ("SnapshotIdentifier", "ghost"),
                ],
            ))
            .err()
            .expect("missing snapshot should error");
        assert_eq!(err.code(), "DBClusterSnapshotNotFoundFault");
    }

    #[test]
    fn restore_db_cluster_to_point_in_time_clones_source() {
        let svc = svc();
        create_cluster(&svc, "src");
        svc.handle_extra_action(&req(
            "ModifyDBCluster",
            &[("DBClusterIdentifier", "src"), ("EngineVersion", "16.2")],
        ))
        .expect("ModifyDBCluster");
        svc.handle_extra_action(&req(
            "RestoreDBClusterToPointInTime",
            &[
                ("DBClusterIdentifier", "pit"),
                ("SourceDBClusterIdentifier", "src"),
                ("UseLatestRestorableTime", "true"),
            ],
        ))
        .expect("RestoreDBClusterToPointInTime");
        let v = cluster_value(&svc, "pit");
        assert_eq!(v["DBClusterIdentifier"].as_str(), Some("pit"));
        assert_eq!(v["EngineVersion"].as_str(), Some("16.2"));
        assert_eq!(v["Status"].as_str(), Some("available"));
        assert_eq!(v["UseLatestRestorableTime"].as_str(), Some("true"));
    }

    #[test]
    fn restore_db_cluster_to_point_in_time_unknown_source_errors() {
        let svc = svc();
        let err = svc
            .handle_extra_action(&req(
                "RestoreDBClusterToPointInTime",
                &[
                    ("DBClusterIdentifier", "pit"),
                    ("SourceDBClusterIdentifier", "ghost"),
                ],
            ))
            .err()
            .expect("missing source should error");
        assert_eq!(err.code(), "DBClusterNotFoundFault");
    }
}
