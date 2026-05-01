use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use http::StatusCode;
use parking_lot::RwLock;
use serde_json::{json, Value};

use fakecloud_core::service::{AwsRequest, AwsResponse, AwsService, AwsServiceError};

use crate::state::{
    Column, Database, GlueAccounts, Partition, SerdeInfo, SharedGlueState, StorageDescriptor, Table,
};

const SUPPORTED_ACTIONS: &[&str] = &[
    "CreateDatabase",
    "GetDatabase",
    "GetDatabases",
    "UpdateDatabase",
    "DeleteDatabase",
    "CreateTable",
    "GetTable",
    "GetTables",
    "UpdateTable",
    "DeleteTable",
    "CreatePartition",
    "GetPartition",
    "GetPartitions",
    "UpdatePartition",
    "DeletePartition",
    "BatchGetPartition",
    "BatchCreatePartition",
];

pub struct GlueService {
    state: SharedGlueState,
}

impl GlueService {
    pub fn new(state: SharedGlueState) -> Self {
        Self { state }
    }

    pub fn shared_state(&self) -> SharedGlueState {
        Arc::clone(&self.state)
    }
}

impl Default for GlueService {
    fn default() -> Self {
        Self::new(Arc::new(RwLock::new(GlueAccounts::new())))
    }
}

#[async_trait]
impl AwsService for GlueService {
    fn service_name(&self) -> &str {
        "glue"
    }

    fn supported_actions(&self) -> &[&str] {
        SUPPORTED_ACTIONS
    }

    async fn handle(&self, req: AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        match req.action.as_str() {
            "CreateDatabase" => self.create_database(&req),
            "GetDatabase" => self.get_database(&req),
            "GetDatabases" => self.get_databases(&req),
            "UpdateDatabase" => self.update_database(&req),
            "DeleteDatabase" => self.delete_database(&req),
            "CreateTable" => self.create_table(&req),
            "GetTable" => self.get_table(&req),
            "GetTables" => self.get_tables(&req),
            "UpdateTable" => self.update_table(&req),
            "DeleteTable" => self.delete_table(&req),
            "CreatePartition" => self.create_partition(&req),
            "GetPartition" => self.get_partition(&req),
            "GetPartitions" => self.get_partitions(&req),
            "UpdatePartition" => self.update_partition(&req),
            "DeletePartition" => self.delete_partition(&req),
            "BatchGetPartition" => self.batch_get_partition(&req),
            "BatchCreatePartition" => self.batch_create_partition(&req),
            other => Err(AwsServiceError::action_not_implemented("glue", other)),
        }
    }
}

fn missing(field: &str) -> AwsServiceError {
    AwsServiceError::aws_error(
        StatusCode::BAD_REQUEST,
        "InvalidInputException",
        format!("Missing required field: {field}"),
    )
}

fn entity_not_found(msg: impl Into<String>) -> AwsServiceError {
    AwsServiceError::aws_error(
        StatusCode::BAD_REQUEST,
        "EntityNotFoundException",
        msg.into(),
    )
}

fn already_exists(msg: impl Into<String>) -> AwsServiceError {
    AwsServiceError::aws_error(
        StatusCode::BAD_REQUEST,
        "AlreadyExistsException",
        msg.into(),
    )
}

fn parse_string_map(val: &Value) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    if let Some(obj) = val.as_object() {
        for (k, v) in obj {
            if let Some(s) = v.as_str() {
                m.insert(k.clone(), s.to_string());
            }
        }
    }
    m
}

fn parse_columns(val: &Value) -> Vec<Column> {
    let Some(arr) = val.as_array() else {
        return Vec::new();
    };
    arr.iter()
        .map(|c| Column {
            name: c["Name"].as_str().unwrap_or_default().to_string(),
            column_type: c["Type"].as_str().unwrap_or_default().to_string(),
            comment: c["Comment"].as_str().map(|s| s.to_string()),
        })
        .collect()
}

fn parse_storage_descriptor(val: &Value) -> Option<StorageDescriptor> {
    if !val.is_object() {
        return None;
    }
    let serde_info = if val["SerdeInfo"].is_object() {
        Some(SerdeInfo {
            name: val["SerdeInfo"]["Name"].as_str().map(|s| s.to_string()),
            serialization_library: val["SerdeInfo"]["SerializationLibrary"]
                .as_str()
                .map(|s| s.to_string()),
            parameters: parse_string_map(&val["SerdeInfo"]["Parameters"]),
        })
    } else {
        None
    };
    Some(StorageDescriptor {
        columns: parse_columns(&val["Columns"]),
        location: val["Location"].as_str().map(|s| s.to_string()),
        input_format: val["InputFormat"].as_str().map(|s| s.to_string()),
        output_format: val["OutputFormat"].as_str().map(|s| s.to_string()),
        compressed: val["Compressed"].as_bool(),
        serde_info,
        parameters: parse_string_map(&val["Parameters"]),
    })
}

fn columns_json(cols: &[Column]) -> Value {
    Value::Array(
        cols.iter()
            .map(|c| {
                let mut o = json!({"Name": c.name, "Type": c.column_type});
                if let Some(ref cm) = c.comment {
                    o["Comment"] = json!(cm);
                }
                o
            })
            .collect(),
    )
}

fn storage_descriptor_json(sd: &StorageDescriptor) -> Value {
    let mut o = json!({
        "Columns": columns_json(&sd.columns),
        "Parameters": sd.parameters,
    });
    if let Some(ref l) = sd.location {
        o["Location"] = json!(l);
    }
    if let Some(ref fmt) = sd.input_format {
        o["InputFormat"] = json!(fmt);
    }
    if let Some(ref fmt) = sd.output_format {
        o["OutputFormat"] = json!(fmt);
    }
    if let Some(c) = sd.compressed {
        o["Compressed"] = json!(c);
    }
    if let Some(ref si) = sd.serde_info {
        let mut sj = json!({"Parameters": si.parameters});
        if let Some(ref n) = si.name {
            sj["Name"] = json!(n);
        }
        if let Some(ref l) = si.serialization_library {
            sj["SerializationLibrary"] = json!(l);
        }
        o["SerdeInfo"] = sj;
    }
    o
}

fn database_json(db: &Database) -> Value {
    let mut o = json!({
        "Name": db.name,
        "CatalogId": db.catalog_id,
        "Parameters": db.parameters,
        "CreateTime": db.created_at.timestamp() as f64,
    });
    if let Some(ref d) = db.description {
        o["Description"] = json!(d);
    }
    if let Some(ref l) = db.location_uri {
        o["LocationUri"] = json!(l);
    }
    o
}

fn table_json(t: &Table) -> Value {
    let mut o = json!({
        "Name": t.name,
        "DatabaseName": t.database_name,
        "Retention": t.retention,
        "Parameters": t.parameters,
        "PartitionKeys": columns_json(&t.partition_keys),
        "CreateTime": t.create_time.timestamp() as f64,
        "UpdateTime": t.update_time.timestamp() as f64,
    });
    if let Some(ref d) = t.description {
        o["Description"] = json!(d);
    }
    if let Some(ref ow) = t.owner {
        o["Owner"] = json!(ow);
    }
    if let Some(ref tt) = t.table_type {
        o["TableType"] = json!(tt);
    }
    if let Some(ref vot) = t.view_original_text {
        o["ViewOriginalText"] = json!(vot);
    }
    if let Some(ref vet) = t.view_expanded_text {
        o["ViewExpandedText"] = json!(vet);
    }
    if let Some(ref sd) = t.storage_descriptor {
        o["StorageDescriptor"] = storage_descriptor_json(sd);
    }
    if let Some(la) = t.last_access_time {
        o["LastAccessTime"] = json!(la.timestamp() as f64);
    }
    o
}

fn partition_json(p: &Partition) -> Value {
    let mut o = json!({
        "Values": p.values,
        "DatabaseName": p.database_name,
        "TableName": p.table_name,
        "Parameters": p.parameters,
        "CreationTime": p.create_time.timestamp() as f64,
    });
    if let Some(la) = p.last_access_time {
        o["LastAccessTime"] = json!(la.timestamp() as f64);
    }
    if let Some(ref sd) = p.storage_descriptor {
        o["StorageDescriptor"] = storage_descriptor_json(sd);
    }
    o
}

fn partition_key(values: &[String]) -> String {
    // Length-prefix each value so partitions whose values contain `/` (or any
    // separator) cannot collide with neighbouring partitions.
    let mut s = String::new();
    for v in values {
        s.push_str(&v.len().to_string());
        s.push(':');
        s.push_str(v);
        s.push('\u{1f}');
    }
    s
}

fn parse_partition_values(json: &Value, field: &str) -> Result<Vec<String>, AwsServiceError> {
    let arr = json.as_array().ok_or_else(|| missing(field))?;
    if arr.is_empty() {
        return Err(missing(field));
    }
    arr.iter()
        .map(|v| {
            v.as_str()
                .map(|s| s.to_string())
                .ok_or_else(|| missing(field))
        })
        .collect()
}

impl GlueService {
    fn create_database(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let input = &body["DatabaseInput"];
        let name = input["Name"]
            .as_str()
            .ok_or_else(|| missing("DatabaseInput.Name"))?
            .to_string();

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id, &req.region);
        let dbs = state.dbs_in_mut(&req.region);
        if dbs.contains_key(&name) {
            return Err(already_exists(format!("Database {name} already exists")));
        }
        dbs.insert(
            name.clone(),
            Database {
                name,
                description: input["Description"].as_str().map(|s| s.to_string()),
                location_uri: input["LocationUri"].as_str().map(|s| s.to_string()),
                parameters: parse_string_map(&input["Parameters"]),
                created_at: Utc::now(),
                catalog_id: req.account_id.clone(),
                tables: BTreeMap::new(),
            },
        );
        Ok(AwsResponse::ok_json(json!({})))
    }

    fn get_database(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let name = body["Name"].as_str().ok_or_else(|| missing("Name"))?;
        let accounts = self.state.read();
        let state = accounts
            .get(&req.account_id)
            .ok_or_else(|| entity_not_found(format!("Database {name} not found")))?;
        let dbs = state
            .dbs_in(&req.region)
            .ok_or_else(|| entity_not_found(format!("Database {name} not found")))?;
        let db = dbs
            .get(name)
            .ok_or_else(|| entity_not_found(format!("Database {name} not found")))?;
        Ok(AwsResponse::ok_json(json!({
            "Database": database_json(db)
        })))
    }

    fn get_databases(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let accounts = self.state.read();
        let dbs: Vec<Value> = accounts
            .get(&req.account_id)
            .and_then(|s| s.dbs_in(&req.region))
            .map(|map| map.values().map(database_json).collect())
            .unwrap_or_default();
        Ok(AwsResponse::ok_json(json!({"DatabaseList": dbs})))
    }

    fn update_database(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let name = body["Name"].as_str().ok_or_else(|| missing("Name"))?;
        let input = &body["DatabaseInput"];
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id, &req.region);
        let dbs = state.dbs_in_mut(&req.region);
        let db = dbs
            .get_mut(name)
            .ok_or_else(|| entity_not_found(format!("Database {name} not found")))?;
        if let Some(d) = input["Description"].as_str() {
            db.description = Some(d.to_string());
        }
        if let Some(l) = input["LocationUri"].as_str() {
            db.location_uri = Some(l.to_string());
        }
        if input["Parameters"].is_object() {
            db.parameters = parse_string_map(&input["Parameters"]);
        }
        Ok(AwsResponse::ok_json(json!({})))
    }

    fn delete_database(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let name = body["Name"].as_str().ok_or_else(|| missing("Name"))?;
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id, &req.region);
        if state.dbs_in_mut(&req.region).remove(name).is_none() {
            return Err(entity_not_found(format!("Database {name} not found")));
        }
        Ok(AwsResponse::ok_json(json!({})))
    }

    fn create_table(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let db_name = body["DatabaseName"]
            .as_str()
            .ok_or_else(|| missing("DatabaseName"))?
            .to_string();
        let input = &body["TableInput"];
        let name = input["Name"]
            .as_str()
            .ok_or_else(|| missing("TableInput.Name"))?
            .to_string();
        let now = Utc::now();
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id, &req.region);
        let dbs = state.dbs_in_mut(&req.region);
        let db = dbs
            .get_mut(&db_name)
            .ok_or_else(|| entity_not_found(format!("Database {db_name} not found")))?;
        if db.tables.contains_key(&name) {
            return Err(already_exists(format!("Table {name} already exists")));
        }
        db.tables.insert(
            name.clone(),
            Table {
                name,
                database_name: db_name,
                description: input["Description"].as_str().map(|s| s.to_string()),
                owner: input["Owner"].as_str().map(|s| s.to_string()),
                create_time: now,
                update_time: now,
                last_access_time: None,
                retention: input["Retention"].as_i64().unwrap_or(0),
                storage_descriptor: parse_storage_descriptor(&input["StorageDescriptor"]),
                partition_keys: parse_columns(&input["PartitionKeys"]),
                view_original_text: input["ViewOriginalText"].as_str().map(|s| s.to_string()),
                view_expanded_text: input["ViewExpandedText"].as_str().map(|s| s.to_string()),
                table_type: input["TableType"].as_str().map(|s| s.to_string()),
                parameters: parse_string_map(&input["Parameters"]),
                partitions: BTreeMap::new(),
            },
        );
        Ok(AwsResponse::ok_json(json!({})))
    }

    fn get_table(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let db_name = body["DatabaseName"]
            .as_str()
            .ok_or_else(|| missing("DatabaseName"))?;
        let name = body["Name"].as_str().ok_or_else(|| missing("Name"))?;
        let accounts = self.state.read();
        let state = accounts
            .get(&req.account_id)
            .ok_or_else(|| entity_not_found(format!("Table {name} not found")))?;
        let dbs = state
            .dbs_in(&req.region)
            .ok_or_else(|| entity_not_found(format!("Table {name} not found")))?;
        let db = dbs
            .get(db_name)
            .ok_or_else(|| entity_not_found(format!("Database {db_name} not found")))?;
        let t = db
            .tables
            .get(name)
            .ok_or_else(|| entity_not_found(format!("Table {name} not found")))?;
        Ok(AwsResponse::ok_json(json!({"Table": table_json(t)})))
    }

    fn get_tables(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let db_name = body["DatabaseName"]
            .as_str()
            .ok_or_else(|| missing("DatabaseName"))?;
        let accounts = self.state.read();
        let tables: Vec<Value> = accounts
            .get(&req.account_id)
            .and_then(|s| s.dbs_in(&req.region))
            .and_then(|dbs| dbs.get(db_name))
            .map(|db| db.tables.values().map(table_json).collect())
            .unwrap_or_default();
        Ok(AwsResponse::ok_json(json!({"TableList": tables})))
    }

    fn update_table(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let db_name = body["DatabaseName"]
            .as_str()
            .ok_or_else(|| missing("DatabaseName"))?;
        let input = &body["TableInput"];
        let name = input["Name"]
            .as_str()
            .ok_or_else(|| missing("TableInput.Name"))?;
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id, &req.region);
        let dbs = state.dbs_in_mut(&req.region);
        let db = dbs
            .get_mut(db_name)
            .ok_or_else(|| entity_not_found(format!("Database {db_name} not found")))?;
        let t = db
            .tables
            .get_mut(name)
            .ok_or_else(|| entity_not_found(format!("Table {name} not found")))?;
        t.update_time = Utc::now();
        if let Some(d) = input["Description"].as_str() {
            t.description = Some(d.to_string());
        }
        if let Some(o) = input["Owner"].as_str() {
            t.owner = Some(o.to_string());
        }
        if let Some(tt) = input["TableType"].as_str() {
            t.table_type = Some(tt.to_string());
        }
        if input["StorageDescriptor"].is_object() {
            t.storage_descriptor = parse_storage_descriptor(&input["StorageDescriptor"]);
        }
        if input["Parameters"].is_object() {
            t.parameters = parse_string_map(&input["Parameters"]);
        }
        if input["PartitionKeys"].is_array() {
            t.partition_keys = parse_columns(&input["PartitionKeys"]);
        }
        Ok(AwsResponse::ok_json(json!({})))
    }

    fn delete_table(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let db_name = body["DatabaseName"]
            .as_str()
            .ok_or_else(|| missing("DatabaseName"))?;
        let name = body["Name"].as_str().ok_or_else(|| missing("Name"))?;
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id, &req.region);
        let dbs = state.dbs_in_mut(&req.region);
        let db = dbs
            .get_mut(db_name)
            .ok_or_else(|| entity_not_found(format!("Database {db_name} not found")))?;
        if db.tables.remove(name).is_none() {
            return Err(entity_not_found(format!("Table {name} not found")));
        }
        Ok(AwsResponse::ok_json(json!({})))
    }

    fn create_partition(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let db_name = body["DatabaseName"]
            .as_str()
            .ok_or_else(|| missing("DatabaseName"))?
            .to_string();
        let table_name = body["TableName"]
            .as_str()
            .ok_or_else(|| missing("TableName"))?
            .to_string();
        let input = &body["PartitionInput"];
        let values = parse_partition_values(&input["Values"], "PartitionInput.Values")?;
        let key = partition_key(&values);
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id, &req.region);
        let dbs = state.dbs_in_mut(&req.region);
        let db = dbs
            .get_mut(&db_name)
            .ok_or_else(|| entity_not_found(format!("Database {db_name} not found")))?;
        let table = db
            .tables
            .get_mut(&table_name)
            .ok_or_else(|| entity_not_found(format!("Table {table_name} not found")))?;
        if table.partitions.contains_key(&key) {
            return Err(already_exists(format!("Partition {key} already exists")));
        }
        table.partitions.insert(
            key,
            Partition {
                values,
                database_name: db_name,
                table_name,
                create_time: Utc::now(),
                last_access_time: None,
                storage_descriptor: parse_storage_descriptor(&input["StorageDescriptor"]),
                parameters: parse_string_map(&input["Parameters"]),
            },
        );
        Ok(AwsResponse::ok_json(json!({})))
    }

    fn get_partition(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let db_name = body["DatabaseName"]
            .as_str()
            .ok_or_else(|| missing("DatabaseName"))?;
        let table_name = body["TableName"]
            .as_str()
            .ok_or_else(|| missing("TableName"))?;
        let values = parse_partition_values(&body["PartitionValues"], "PartitionValues")?;
        let key = partition_key(&values);
        let accounts = self.state.read();
        let state = accounts
            .get(&req.account_id)
            .ok_or_else(|| entity_not_found("Partition not found"))?;
        let dbs = state
            .dbs_in(&req.region)
            .ok_or_else(|| entity_not_found("Partition not found"))?;
        let db = dbs
            .get(db_name)
            .ok_or_else(|| entity_not_found(format!("Database {db_name} not found")))?;
        let table = db
            .tables
            .get(table_name)
            .ok_or_else(|| entity_not_found(format!("Table {table_name} not found")))?;
        let p = table
            .partitions
            .get(&key)
            .ok_or_else(|| entity_not_found("Partition not found"))?;
        Ok(AwsResponse::ok_json(
            json!({"Partition": partition_json(p)}),
        ))
    }

    fn get_partitions(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let db_name = body["DatabaseName"]
            .as_str()
            .ok_or_else(|| missing("DatabaseName"))?;
        let table_name = body["TableName"]
            .as_str()
            .ok_or_else(|| missing("TableName"))?;
        let accounts = self.state.read();
        let parts: Vec<Value> = accounts
            .get(&req.account_id)
            .and_then(|s| s.dbs_in(&req.region))
            .and_then(|dbs| dbs.get(db_name))
            .and_then(|db| db.tables.get(table_name))
            .map(|table| table.partitions.values().map(partition_json).collect())
            .unwrap_or_default();
        Ok(AwsResponse::ok_json(json!({"Partitions": parts})))
    }

    fn update_partition(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let db_name = body["DatabaseName"]
            .as_str()
            .ok_or_else(|| missing("DatabaseName"))?;
        let table_name = body["TableName"]
            .as_str()
            .ok_or_else(|| missing("TableName"))?;
        let value_list = parse_partition_values(&body["PartitionValueList"], "PartitionValueList")?;
        let key = partition_key(&value_list);
        let input = &body["PartitionInput"];
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id, &req.region);
        let dbs = state.dbs_in_mut(&req.region);
        let db = dbs
            .get_mut(db_name)
            .ok_or_else(|| entity_not_found(format!("Database {db_name} not found")))?;
        let table = db
            .tables
            .get_mut(table_name)
            .ok_or_else(|| entity_not_found(format!("Table {table_name} not found")))?;
        let part = table
            .partitions
            .get_mut(&key)
            .ok_or_else(|| entity_not_found("Partition not found"))?;
        if input["StorageDescriptor"].is_object() {
            part.storage_descriptor = parse_storage_descriptor(&input["StorageDescriptor"]);
        }
        if input["Parameters"].is_object() {
            part.parameters = parse_string_map(&input["Parameters"]);
        }
        Ok(AwsResponse::ok_json(json!({})))
    }

    fn delete_partition(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let db_name = body["DatabaseName"]
            .as_str()
            .ok_or_else(|| missing("DatabaseName"))?;
        let table_name = body["TableName"]
            .as_str()
            .ok_or_else(|| missing("TableName"))?;
        let values = parse_partition_values(&body["PartitionValues"], "PartitionValues")?;
        let key = partition_key(&values);
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id, &req.region);
        let dbs = state.dbs_in_mut(&req.region);
        let db = dbs
            .get_mut(db_name)
            .ok_or_else(|| entity_not_found(format!("Database {db_name} not found")))?;
        let table = db
            .tables
            .get_mut(table_name)
            .ok_or_else(|| entity_not_found(format!("Table {table_name} not found")))?;
        if table.partitions.remove(&key).is_none() {
            return Err(entity_not_found("Partition not found"));
        }
        Ok(AwsResponse::ok_json(json!({})))
    }

    fn batch_get_partition(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let db_name = body["DatabaseName"]
            .as_str()
            .ok_or_else(|| missing("DatabaseName"))?;
        let table_name = body["TableName"]
            .as_str()
            .ok_or_else(|| missing("TableName"))?;
        let to_get = body["PartitionsToGet"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        let accounts = self.state.read();
        let mut found = Vec::new();
        let mut not_found = Vec::new();
        let table = accounts
            .get(&req.account_id)
            .and_then(|s| s.dbs_in(&req.region))
            .and_then(|dbs| dbs.get(db_name))
            .and_then(|db| db.tables.get(table_name));
        for pv in &to_get {
            let values = parse_partition_values(&pv["Values"], "PartitionsToGet.Values")?;
            let key = partition_key(&values);
            match table.and_then(|t| t.partitions.get(&key)) {
                Some(p) => found.push(partition_json(p)),
                None => not_found.push(json!({"Values": values})),
            }
        }
        Ok(AwsResponse::ok_json(json!({
            "Partitions": found,
            "UnprocessedKeys": not_found,
        })))
    }

    fn batch_create_partition(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let db_name = body["DatabaseName"]
            .as_str()
            .ok_or_else(|| missing("DatabaseName"))?
            .to_string();
        let table_name = body["TableName"]
            .as_str()
            .ok_or_else(|| missing("TableName"))?
            .to_string();
        let inputs = body["PartitionInputList"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        let mut errors = Vec::new();
        let now = Utc::now();
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id, &req.region);
        let dbs = state.dbs_in_mut(&req.region);
        let db = dbs
            .get_mut(&db_name)
            .ok_or_else(|| entity_not_found(format!("Database {db_name} not found")))?;
        let table = db
            .tables
            .get_mut(&table_name)
            .ok_or_else(|| entity_not_found(format!("Table {table_name} not found")))?;
        for input in inputs {
            let values = match parse_partition_values(&input["Values"], "PartitionInput.Values") {
                Ok(v) => v,
                Err(_) => {
                    errors.push(json!({
                        "PartitionValues": Vec::<String>::new(),
                        "ErrorDetail": {
                            "ErrorCode": "InvalidInputException",
                            "ErrorMessage": "Values must be a non-empty list of strings",
                        },
                    }));
                    continue;
                }
            };
            let key = partition_key(&values);
            if table.partitions.contains_key(&key) {
                errors.push(json!({
                    "PartitionValues": values,
                    "ErrorDetail": {
                        "ErrorCode": "AlreadyExistsException",
                        "ErrorMessage": format!("Partition {key} already exists"),
                    },
                }));
                continue;
            }
            table.partitions.insert(
                key,
                Partition {
                    values,
                    database_name: db_name.clone(),
                    table_name: table_name.clone(),
                    create_time: now,
                    last_access_time: None,
                    storage_descriptor: parse_storage_descriptor(&input["StorageDescriptor"]),
                    parameters: parse_string_map(&input["Parameters"]),
                },
            );
        }
        Ok(AwsResponse::ok_json(json!({"Errors": errors})))
    }
}
