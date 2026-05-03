use std::collections::HashMap;

use http::StatusCode;
use serde_json::{json, Value};

use fakecloud_core::service::{AwsRequest, AwsResponse, AwsServiceError};
use fakecloud_core::validation::*;

use crate::state::AttributeValue;

/// A queued Kinesis delivery for a single transact write — fired after
/// the apply phase succeeds and the write lock is dropped. Tuple shape:
/// (target, event_name, keys, old_image, new_image).
type PendingKinesis = (
    super::KinesisDeliveryTarget,
    String,
    HashMap<String, AttributeValue>,
    Option<HashMap<String, AttributeValue>>,
    Option<HashMap<String, AttributeValue>>,
);

use super::{
    apply_update_expression, build_consumed_capacity, evaluate_condition, execute_partiql_in_state,
    execute_partiql_statement, extract_key, get_table, get_table_mut,
    parse_expression_attribute_names, parse_expression_attribute_values, require_str,
    return_consumed_mode, return_icm_mode, DynamoDbService,
};

impl DynamoDbService {
    pub(super) fn batch_get_item(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = Self::parse_body(req)?;

        validate_optional_enum_value(
            "returnConsumedCapacity",
            &body["ReturnConsumedCapacity"],
            &["INDEXES", "TOTAL", "NONE"],
        )?;

        let return_consumed = return_consumed_mode(&body).to_string();

        let request_items = body["RequestItems"]
            .as_object()
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "ValidationException",
                    "RequestItems is required",
                )
            })?
            .clone();

        let accounts = self.state.read();
        let empty_ddb = crate::state::DynamoDbState::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty_ddb);
        let mut responses: HashMap<String, Vec<Value>> = HashMap::new();
        let mut consumed_capacity: Vec<Value> = Vec::new();

        for (table_name, params) in &request_items {
            let table = get_table(&state.tables, table_name)?;
            let keys = params["Keys"].as_array().ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "ValidationException",
                    "Keys is required",
                )
            })?;

            let mut items = Vec::new();
            for key_val in keys {
                let key: HashMap<String, AttributeValue> =
                    serde_json::from_value(key_val.clone()).unwrap_or_default();
                if let Some(idx) = table.find_item_index(&key) {
                    items.push(json!(table.items[idx]));
                }
            }
            let key_count = keys.len().max(1) as f64;
            responses.insert(table_name.clone(), items);

            let cc = build_consumed_capacity(&return_consumed, table_name, key_count * 0.5, 0.0);
            if !cc.is_null() {
                consumed_capacity.push(cc);
            }
        }

        let mut result = json!({
            "Responses": responses,
            "UnprocessedKeys": {},
        });

        if !consumed_capacity.is_empty() {
            result["ConsumedCapacity"] = json!(consumed_capacity);
        }

        Self::ok_json(result)
    }

    pub(super) fn batch_write_item(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = Self::parse_body(req)?;

        validate_optional_enum_value(
            "returnConsumedCapacity",
            &body["ReturnConsumedCapacity"],
            &["INDEXES", "TOTAL", "NONE"],
        )?;
        validate_optional_enum_value(
            "returnItemCollectionMetrics",
            &body["ReturnItemCollectionMetrics"],
            &["SIZE", "NONE"],
        )?;

        let return_consumed = return_consumed_mode(&body).to_string();
        let return_icm = return_icm_mode(&body).to_string();

        let request_items = body["RequestItems"]
            .as_object()
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "ValidationException",
                    "RequestItems is required",
                )
            })?
            .clone();

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let mut consumed_capacity: Vec<Value> = Vec::new();
        let mut item_collection_metrics: HashMap<String, Vec<Value>> = HashMap::new();

        for (table_name, requests) in &request_items {
            let table = state.tables.get_mut(table_name.as_str()).ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "ResourceNotFoundException",
                    format!("Requested resource not found: Table: {table_name} not found"),
                )
            })?;

            let reqs = requests.as_array().ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "ValidationException",
                    "Request list must be an array",
                )
            })?;

            let mut write_count = 0u32;
            let mut keys_for_icm: Vec<HashMap<String, AttributeValue>> = Vec::new();
            for request in reqs {
                if let Some(put_req) = request.get("PutRequest") {
                    let item: HashMap<String, AttributeValue> =
                        serde_json::from_value(put_req["Item"].clone()).unwrap_or_default();
                    let key = extract_key(table, &item);
                    keys_for_icm.push(key.clone());
                    if let Some(idx) = table.find_item_index(&key) {
                        table.items[idx] = item;
                    } else {
                        table.items.push(item);
                    }
                    write_count += 1;
                } else if let Some(del_req) = request.get("DeleteRequest") {
                    let key: HashMap<String, AttributeValue> =
                        serde_json::from_value(del_req["Key"].clone()).unwrap_or_default();
                    keys_for_icm.push(key.clone());
                    if let Some(idx) = table.find_item_index(&key) {
                        table.items.remove(idx);
                    }
                    write_count += 1;
                }
            }

            table.recalculate_stats();

            let cc = build_consumed_capacity(
                &return_consumed,
                table_name,
                0.0,
                write_count.max(1) as f64,
            );
            if !cc.is_null() {
                consumed_capacity.push(cc);
            }

            if return_icm == "SIZE" && !table.lsi.is_empty() {
                let entries: Vec<Value> = keys_for_icm
                    .iter()
                    .map(|k| super::helpers::build_item_collection_metrics(&return_icm, table, k))
                    .filter(|v| !v.is_null())
                    .collect();
                if !entries.is_empty() {
                    item_collection_metrics.insert(table_name.clone(), entries);
                }
            }
        }

        let mut result = json!({
            "UnprocessedItems": {},
        });

        if !consumed_capacity.is_empty() {
            result["ConsumedCapacity"] = json!(consumed_capacity);
        }

        if return_icm == "SIZE" && !item_collection_metrics.is_empty() {
            result["ItemCollectionMetrics"] = json!(item_collection_metrics);
        }

        Self::ok_json(result)
    }

    pub(super) fn transact_get_items(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = Self::parse_body(req)?;
        validate_optional_enum_value(
            "returnConsumedCapacity",
            &body["ReturnConsumedCapacity"],
            &["INDEXES", "TOTAL", "NONE"],
        )?;
        let return_consumed = return_consumed_mode(&body).to_string();
        let transact_items = body["TransactItems"].as_array().ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ValidationException",
                "TransactItems is required",
            )
        })?;

        let accounts = self.state.read();
        let empty_ddb = crate::state::DynamoDbState::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty_ddb);
        let mut responses: Vec<Value> = Vec::new();
        let mut per_table_count: HashMap<String, u32> = HashMap::new();

        for ti in transact_items {
            let get = &ti["Get"];
            let table_name = get["TableName"].as_str().ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "ValidationException",
                    "TableName is required in Get",
                )
            })?;
            let key: HashMap<String, AttributeValue> =
                serde_json::from_value(get["Key"].clone()).unwrap_or_default();

            let table = get_table(&state.tables, table_name)?;
            match table.find_item_index(&key) {
                Some(idx) => {
                    responses.push(json!({ "Item": table.items[idx] }));
                }
                None => {
                    responses.push(json!({}));
                }
            }
            *per_table_count.entry(table_name.to_string()).or_insert(0) += 1;
        }

        let mut result = json!({ "Responses": responses });
        let consumed: Vec<Value> = per_table_count
            .iter()
            .filter_map(|(t, n)| {
                let cc = build_consumed_capacity(&return_consumed, t, (*n as f64) * 2.0, 0.0);
                if cc.is_null() {
                    None
                } else {
                    Some(cc)
                }
            })
            .collect();
        if !consumed.is_empty() {
            result["ConsumedCapacity"] = json!(consumed);
        }

        Self::ok_json(result)
    }

    pub(super) fn transact_write_items(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = Self::parse_body(req)?;
        validate_optional_string_length(
            "clientRequestToken",
            body["ClientRequestToken"].as_str(),
            1,
            36,
        )?;
        validate_optional_enum_value(
            "returnConsumedCapacity",
            &body["ReturnConsumedCapacity"],
            &["INDEXES", "TOTAL", "NONE"],
        )?;
        validate_optional_enum_value(
            "returnItemCollectionMetrics",
            &body["ReturnItemCollectionMetrics"],
            &["SIZE", "NONE"],
        )?;
        let return_consumed = return_consumed_mode(&body).to_string();
        let return_icm = return_icm_mode(&body).to_string();
        let transact_items = body["TransactItems"].as_array().ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ValidationException",
                "TransactItems is required",
            )
        })?;

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);

        // Validate every referenced table exists up-front. Without this
        // check a missing TableName on a Put with no condition would fail
        // partway through the apply loop and leave earlier writes
        // committed — TransactWriteItems must be all-or-nothing.
        for ti in transact_items {
            for op_key in ["Put", "Delete", "Update", "ConditionCheck"] {
                if let Some(op) = ti.get(op_key) {
                    let table_name = op["TableName"].as_str().unwrap_or_default();
                    get_table(&state.tables, table_name)?;
                }
            }
        }

        // First pass: validate all conditions
        let mut cancellation_reasons: Vec<Value> = Vec::new();
        let mut any_failed = false;
        let mut per_table_writes: HashMap<String, u32> = HashMap::new();

        for ti in transact_items {
            if let Some(put) = ti.get("Put") {
                let table_name = put["TableName"].as_str().unwrap_or_default();
                let item: HashMap<String, AttributeValue> =
                    serde_json::from_value(put["Item"].clone()).unwrap_or_default();
                let condition = put["ConditionExpression"].as_str();

                if let Some(cond) = condition {
                    let table = get_table(&state.tables, table_name)?;
                    let expr_attr_names = parse_expression_attribute_names(put);
                    let expr_attr_values = parse_expression_attribute_values(put);
                    let key = extract_key(table, &item);
                    let existing = table.find_item_index(&key).map(|i| &table.items[i]);
                    if evaluate_condition(cond, existing, &expr_attr_names, &expr_attr_values)
                        .is_err()
                    {
                        cancellation_reasons.push(json!({
                            "Code": "ConditionalCheckFailed",
                            "Message": "The conditional request failed"
                        }));
                        any_failed = true;
                        continue;
                    }
                }
                cancellation_reasons.push(json!({ "Code": "None" }));
            } else if let Some(delete) = ti.get("Delete") {
                let table_name = delete["TableName"].as_str().unwrap_or_default();
                let key: HashMap<String, AttributeValue> =
                    serde_json::from_value(delete["Key"].clone()).unwrap_or_default();
                let condition = delete["ConditionExpression"].as_str();

                if let Some(cond) = condition {
                    let table = get_table(&state.tables, table_name)?;
                    let expr_attr_names = parse_expression_attribute_names(delete);
                    let expr_attr_values = parse_expression_attribute_values(delete);
                    let existing = table.find_item_index(&key).map(|i| &table.items[i]);
                    if evaluate_condition(cond, existing, &expr_attr_names, &expr_attr_values)
                        .is_err()
                    {
                        cancellation_reasons.push(json!({
                            "Code": "ConditionalCheckFailed",
                            "Message": "The conditional request failed"
                        }));
                        any_failed = true;
                        continue;
                    }
                }
                cancellation_reasons.push(json!({ "Code": "None" }));
            } else if let Some(update) = ti.get("Update") {
                let table_name = update["TableName"].as_str().unwrap_or_default();
                let key: HashMap<String, AttributeValue> =
                    serde_json::from_value(update["Key"].clone()).unwrap_or_default();
                let condition = update["ConditionExpression"].as_str();

                if let Some(cond) = condition {
                    let table = get_table(&state.tables, table_name)?;
                    let expr_attr_names = parse_expression_attribute_names(update);
                    let expr_attr_values = parse_expression_attribute_values(update);
                    let existing = table.find_item_index(&key).map(|i| &table.items[i]);
                    if evaluate_condition(cond, existing, &expr_attr_names, &expr_attr_values)
                        .is_err()
                    {
                        cancellation_reasons.push(json!({
                            "Code": "ConditionalCheckFailed",
                            "Message": "The conditional request failed"
                        }));
                        any_failed = true;
                        continue;
                    }
                }
                cancellation_reasons.push(json!({ "Code": "None" }));
            } else if let Some(check) = ti.get("ConditionCheck") {
                let table_name = check["TableName"].as_str().unwrap_or_default();
                let key: HashMap<String, AttributeValue> =
                    serde_json::from_value(check["Key"].clone()).unwrap_or_default();
                let cond = check["ConditionExpression"].as_str().unwrap_or_default();

                let table = get_table(&state.tables, table_name)?;
                let expr_attr_names = parse_expression_attribute_names(check);
                let expr_attr_values = parse_expression_attribute_values(check);
                let existing = table.find_item_index(&key).map(|i| &table.items[i]);
                if evaluate_condition(cond, existing, &expr_attr_names, &expr_attr_values).is_err()
                {
                    cancellation_reasons.push(json!({
                        "Code": "ConditionalCheckFailed",
                        "Message": "The conditional request failed"
                    }));
                    any_failed = true;
                    continue;
                }
                cancellation_reasons.push(json!({ "Code": "None" }));
            } else {
                cancellation_reasons.push(json!({ "Code": "None" }));
            }
        }

        if any_failed {
            let error_body = json!({
                "__type": "TransactionCanceledException",
                "message": "Transaction cancelled, please refer cancellation reasons for specific reasons [ConditionalCheckFailed]",
                "CancellationReasons": cancellation_reasons
            });
            return Ok(AwsResponse::json(
                StatusCode::BAD_REQUEST,
                serde_json::to_vec(&error_body).unwrap(),
            ));
        }

        // Snapshot the items vector of every referenced table so we can
        // revert on any apply-phase failure (e.g. an unparseable
        // UpdateExpression). DDB transactions are all-or-nothing — without
        // this, an UpdateExpression error after a successful Put would
        // leave the Put committed.
        let mut snapshots: HashMap<String, Vec<HashMap<String, AttributeValue>>> = HashMap::new();
        for ti in transact_items {
            for op_key in ["Put", "Delete", "Update"] {
                if let Some(op) = ti.get(op_key) {
                    let table_name = op["TableName"].as_str().unwrap_or_default();
                    snapshots.entry(table_name.to_string()).or_insert_with(|| {
                        state
                            .tables
                            .get(table_name)
                            .map(|t| t.items.clone())
                            .unwrap_or_default()
                    });
                }
            }
        }

        // Stream records pending append + kinesis deliveries pending
        // dispatch — collected during apply, fired after all writes
        // succeed so a mid-batch failure leaves no observable side
        // effects.
        let mut pending_stream: Vec<(String, crate::state::StreamRecord)> = Vec::new();
        let mut pending_kinesis: Vec<PendingKinesis> = Vec::new();
        let region = req.region.clone();

        // Second pass: apply all writes
        let apply_result = (|| -> Result<(), AwsServiceError> {
            for ti in transact_items {
                if let Some(put) = ti.get("Put") {
                    let table_name = put["TableName"].as_str().unwrap_or_default();
                    let item: HashMap<String, AttributeValue> =
                        serde_json::from_value(put["Item"].clone()).unwrap_or_default();
                    let table = get_table_mut(&mut state.tables, table_name)?;
                    let key = extract_key(table, &item);
                    let old_image = table.find_item_index(&key).map(|i| table.items[i].clone());
                    let is_modify = old_image.is_some();
                    if let Some(idx) = table.find_item_index(&key) {
                        table.items[idx] = item.clone();
                    } else {
                        table.items.push(item.clone());
                    }
                    table.recalculate_stats();
                    let event_name = if is_modify { "MODIFY" } else { "INSERT" };
                    if let Some(record) = crate::streams::generate_stream_record(
                        table,
                        event_name,
                        key.clone(),
                        old_image.clone(),
                        Some(item.clone()),
                        &region,
                    ) {
                        pending_stream.push((table_name.to_string(), record));
                    }
                    if let Some(target) = DynamoDbService::kinesis_target(table) {
                        pending_kinesis.push((
                            target,
                            event_name.to_string(),
                            key,
                            old_image,
                            Some(item),
                        ));
                    }
                    *per_table_writes.entry(table_name.to_string()).or_insert(0) += 1;
                } else if let Some(delete) = ti.get("Delete") {
                    let table_name = delete["TableName"].as_str().unwrap_or_default();
                    let key: HashMap<String, AttributeValue> =
                        serde_json::from_value(delete["Key"].clone()).unwrap_or_default();
                    let table = get_table_mut(&mut state.tables, table_name)?;
                    let old_image = table.find_item_index(&key).map(|i| table.items[i].clone());
                    if let Some(idx) = table.find_item_index(&key) {
                        table.items.remove(idx);
                    }
                    table.recalculate_stats();
                    if old_image.is_some() {
                        if let Some(record) = crate::streams::generate_stream_record(
                            table,
                            "REMOVE",
                            key.clone(),
                            old_image.clone(),
                            None,
                            &region,
                        ) {
                            pending_stream.push((table_name.to_string(), record));
                        }
                        if let Some(target) = DynamoDbService::kinesis_target(table) {
                            pending_kinesis.push((
                                target,
                                "REMOVE".to_string(),
                                key,
                                old_image,
                                None,
                            ));
                        }
                    }
                    *per_table_writes.entry(table_name.to_string()).or_insert(0) += 1;
                } else if let Some(update) = ti.get("Update") {
                    let table_name = update["TableName"].as_str().unwrap_or_default();
                    let key: HashMap<String, AttributeValue> =
                        serde_json::from_value(update["Key"].clone()).unwrap_or_default();
                    let update_expression = update["UpdateExpression"].as_str();
                    let expr_attr_names = parse_expression_attribute_names(update);
                    let expr_attr_values = parse_expression_attribute_values(update);

                    let table = get_table_mut(&mut state.tables, table_name)?;
                    let old_image = table.find_item_index(&key).map(|i| table.items[i].clone());
                    let is_modify = old_image.is_some();
                    let idx = match table.find_item_index(&key) {
                        Some(i) => i,
                        None => {
                            let mut new_item = HashMap::new();
                            for (k, v) in &key {
                                new_item.insert(k.clone(), v.clone());
                            }
                            table.items.push(new_item);
                            table.items.len() - 1
                        }
                    };

                    if let Some(expr) = update_expression {
                        apply_update_expression(
                            &mut table.items[idx],
                            expr,
                            &expr_attr_names,
                            &expr_attr_values,
                        )?;
                    }
                    let new_image = table.items[idx].clone();
                    table.recalculate_stats();
                    let event_name = if is_modify { "MODIFY" } else { "INSERT" };
                    if let Some(record) = crate::streams::generate_stream_record(
                        table,
                        event_name,
                        key.clone(),
                        old_image.clone(),
                        Some(new_image.clone()),
                        &region,
                    ) {
                        pending_stream.push((table_name.to_string(), record));
                    }
                    if let Some(target) = DynamoDbService::kinesis_target(table) {
                        pending_kinesis.push((
                            target,
                            event_name.to_string(),
                            key,
                            old_image,
                            Some(new_image),
                        ));
                    }
                    *per_table_writes.entry(table_name.to_string()).or_insert(0) += 1;
                }
                // ConditionCheck: no write needed
            }
            Ok(())
        })();

        if let Err(err) = apply_result {
            // Revert items on every touched table and bubble the error.
            for (table_name, items) in snapshots {
                if let Some(table) = state.tables.get_mut(&table_name) {
                    table.items = items;
                    table.recalculate_stats();
                }
            }
            return Err(err);
        }

        // Append all pending stream records under each table's
        // stream_records lock now that the transaction has committed.
        for (table_name, record) in pending_stream {
            if let Some(table) = state.tables.get_mut(&table_name) {
                crate::streams::add_stream_record(table, record);
            }
        }

        let mut result = json!({});
        let consumed: Vec<Value> = per_table_writes
            .iter()
            .filter_map(|(t, n)| {
                let cc = build_consumed_capacity(&return_consumed, t, 0.0, (*n as f64) * 2.0);
                if cc.is_null() {
                    None
                } else {
                    Some(cc)
                }
            })
            .collect();
        if !consumed.is_empty() {
            result["ConsumedCapacity"] = json!(consumed);
        }
        if return_icm == "SIZE" {
            let icm: HashMap<String, Vec<Value>> = per_table_writes
                .keys()
                .map(|t| (t.clone(), vec![]))
                .collect();
            result["ItemCollectionMetrics"] = json!(icm);
        }

        // Drop the write lock before firing kinesis deliveries so the
        // delivery bus (which may take a read lock to look up the target
        // stream) doesn't deadlock against us.
        drop(accounts);
        for (target, event_name, keys, old_image, new_image) in pending_kinesis {
            self.deliver_to_kinesis_destinations(
                &target,
                &event_name,
                &keys,
                old_image.as_ref(),
                new_image.as_ref(),
            );
        }

        Self::ok_json(result)
    }

    // ── PartiQL ─────────────────────────────────────────────────────────

    pub(super) fn execute_statement(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = Self::parse_body(req)?;
        let statement = require_str(&body, "Statement")?;
        let parameters = body["Parameters"].as_array().cloned().unwrap_or_default();

        execute_partiql_statement(&self.state, statement, &parameters)
    }

    pub(super) fn batch_execute_statement(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = Self::parse_body(req)?;
        validate_optional_enum_value(
            "returnConsumedCapacity",
            &body["ReturnConsumedCapacity"],
            &["INDEXES", "TOTAL", "NONE"],
        )?;
        let statements = body["Statements"].as_array().ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ValidationException",
                "Statements is required",
            )
        })?;

        let mut responses: Vec<Value> = Vec::new();
        for stmt_obj in statements {
            let statement = stmt_obj["Statement"].as_str().unwrap_or_default();
            let parameters = stmt_obj["Parameters"]
                .as_array()
                .cloned()
                .unwrap_or_default();

            match execute_partiql_statement(&self.state, statement, &parameters) {
                Ok(resp) => {
                    let resp_body: Value =
                        serde_json::from_slice(resp.body.expect_bytes()).unwrap_or_default();
                    responses.push(resp_body);
                }
                Err(e) => {
                    responses.push(json!({
                        "Error": {
                            "Code": "ValidationException",
                            "Message": e.to_string()
                        }
                    }));
                }
            }
        }

        Self::ok_json(json!({ "Responses": responses }))
    }

    pub(super) fn execute_transaction(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = Self::parse_body(req)?;
        validate_optional_string_length(
            "clientRequestToken",
            body["ClientRequestToken"].as_str(),
            1,
            36,
        )?;
        validate_optional_enum_value(
            "returnConsumedCapacity",
            &body["ReturnConsumedCapacity"],
            &["INDEXES", "TOTAL", "NONE"],
        )?;
        let transact_statements = body["TransactStatements"].as_array().ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ValidationException",
                "TransactStatements is required",
            )
        })?;

        // Snapshot every account state on the default account up-front
        // so we can revert in one shot if any statement fails. Cheap
        // because PartiQL targets the default account only (PartiQL has
        // no per-account scoping), and atomicity is required by the
        // spec.
        let mut accounts = self.state.write();
        let state = accounts.default_mut();
        let snapshot_tables = state.tables.clone();

        let region = req.region.clone();
        let mut responses: Vec<Value> = Vec::with_capacity(transact_statements.len());
        let mut pending_stream: Vec<(String, crate::state::StreamRecord)> = Vec::new();
        let mut pending_kinesis: Vec<PendingKinesis> = Vec::new();
        let mut failure: Option<(usize, String)> = None;

        for (i, stmt_obj) in transact_statements.iter().enumerate() {
            let statement = stmt_obj["Statement"].as_str().unwrap_or_default();
            let parameters = stmt_obj["Parameters"]
                .as_array()
                .cloned()
                .unwrap_or_default();

            match execute_partiql_in_state(state, statement, &parameters) {
                Ok(outcome) => {
                    responses.push(outcome.response);
                    let table_name = match outcome.table_name {
                        Some(n) => n,
                        None => continue,
                    };
                    let event_name = match outcome.event_name {
                        Some(e) => e,
                        None => continue,
                    };
                    let keys = outcome.keys.unwrap_or_default();
                    if let Some(table) = state.tables.get(&table_name) {
                        if let Some(record) = crate::streams::generate_stream_record(
                            table,
                            &event_name,
                            keys.clone(),
                            outcome.old_image.clone(),
                            outcome.new_image.clone(),
                            &region,
                        ) {
                            pending_stream.push((table_name.clone(), record));
                        }
                        if let Some(target) = DynamoDbService::kinesis_target(table) {
                            pending_kinesis.push((
                                target,
                                event_name,
                                keys,
                                outcome.old_image,
                                outcome.new_image,
                            ));
                        }
                    }
                }
                Err(e) => {
                    failure = Some((i, e.to_string()));
                    break;
                }
            }
        }

        if let Some((failed_idx, msg)) = failure {
            // Revert: replace the tables map with the pre-transaction
            // snapshot so all earlier statements in this transaction
            // are undone.
            state.tables = snapshot_tables;
            let reasons: Vec<Value> = (0..transact_statements.len())
                .map(|i| {
                    if i == failed_idx {
                        json!({
                            "Code": "ValidationException",
                            "Message": msg.clone(),
                        })
                    } else {
                        json!({ "Code": "None" })
                    }
                })
                .collect();
            let error_body = json!({
                "__type": "TransactionCanceledException",
                "message": "Transaction cancelled due to validation errors",
                "CancellationReasons": reasons
            });
            return Ok(AwsResponse::json(
                StatusCode::BAD_REQUEST,
                serde_json::to_vec(&error_body).unwrap(),
            ));
        }

        // Append pending stream records under each table's lock.
        for (table_name, record) in pending_stream {
            if let Some(table) = state.tables.get_mut(&table_name) {
                crate::streams::add_stream_record(table, record);
            }
        }

        drop(accounts);
        for (target, event_name, keys, old_image, new_image) in pending_kinesis {
            self.deliver_to_kinesis_destinations(
                &target,
                &event_name,
                &keys,
                old_image.as_ref(),
                new_image.as_ref(),
            );
        }

        Self::ok_json(json!({ "Responses": responses }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{DynamoTable, KeySchemaElement, ProvisionedThroughput, SharedDynamoDbState};
    use bytes::Bytes;
    use chrono::Utc;
    use http::{HeaderMap, Method};
    use parking_lot::RwLock;
    use std::collections::BTreeMap;
    use std::sync::Arc;

    fn req_for(action: &str, body: Value) -> AwsRequest {
        AwsRequest {
            service: "dynamodb".into(),
            action: action.into(),
            region: "us-east-1".into(),
            account_id: "123456789012".into(),
            request_id: "r".into(),
            headers: HeaderMap::new(),
            query_params: HashMap::new(),
            body: Bytes::from(serde_json::to_vec(&body).unwrap()),
            body_stream: parking_lot::Mutex::new(None),
            path_segments: vec![],
            raw_path: "/".into(),
            raw_query: String::new(),
            method: Method::POST,
            is_query_protocol: false,
            access_key_id: None,
            principal: None,
        }
    }

    fn make_state() -> SharedDynamoDbState {
        Arc::new(RwLock::new(
            fakecloud_core::multi_account::MultiAccountState::new("123456789012", "us-east-1", ""),
        ))
    }

    fn seed_table_with_stream(state: &SharedDynamoDbState, name: &str) {
        let mut accts = state.write();
        let s = accts.get_or_create("123456789012");
        let table = DynamoTable {
            name: name.to_string(),
            arn: format!("arn:aws:dynamodb:us-east-1:123456789012:table/{name}"),
            table_id: "id".to_string(),
            key_schema: vec![KeySchemaElement {
                attribute_name: "pk".into(),
                key_type: "HASH".into(),
            }],
            attribute_definitions: vec![],
            provisioned_throughput: ProvisionedThroughput {
                read_capacity_units: 0,
                write_capacity_units: 0,
            },
            items: vec![],
            gsi: vec![],
            lsi: vec![],
            tags: BTreeMap::new(),
            created_at: Utc::now(),
            status: "ACTIVE".to_string(),
            item_count: 0,
            size_bytes: 0,
            billing_mode: "PAY_PER_REQUEST".to_string(),
            ttl_attribute: None,
            ttl_enabled: false,
            resource_policy: None,
            pitr_enabled: false,
            kinesis_destinations: vec![],
            contributor_insights_status: "DISABLED".to_string(),
            contributor_insights_counters: BTreeMap::new(),
            stream_enabled: true,
            stream_view_type: Some("NEW_AND_OLD_IMAGES".to_string()),
            stream_arn: Some(format!(
                "arn:aws:dynamodb:us-east-1:123456789012:table/{name}/stream/lbl"
            )),
            stream_records: Arc::new(RwLock::new(Vec::new())),
            sse_type: None,
            sse_kms_key_arn: None,
            deletion_protection_enabled: false,
            on_demand_throughput: None,
        };
        s.tables.insert(name.to_string(), table);
    }

    #[tokio::test]
    async fn transact_write_emits_stream_records_per_write() {
        let state = make_state();
        seed_table_with_stream(&state, "Widgets");
        let svc = DynamoDbService::new(state.clone());

        let req = req_for(
            "TransactWriteItems",
            json!({
                "TransactItems": [
                    {"Put": {"TableName": "Widgets", "Item": {"pk": {"S": "a"}}}},
                    {"Put": {"TableName": "Widgets", "Item": {"pk": {"S": "b"}}}},
                ]
            }),
        );
        svc.transact_write_items(&req).unwrap();

        let accts = state.read();
        let s = accts.get("123456789012").unwrap();
        let table = s.tables.get("Widgets").unwrap();
        let records = table.stream_records.read();
        assert_eq!(records.len(), 2, "one stream record per Put");
        assert!(records.iter().all(|r| r.event_name == "INSERT"));
    }

    #[tokio::test]
    async fn transact_write_unknown_table_rejects_atomically() {
        let state = make_state();
        seed_table_with_stream(&state, "Widgets");
        let svc = DynamoDbService::new(state.clone());

        let req = req_for(
            "TransactWriteItems",
            json!({
                "TransactItems": [
                    {"Put": {"TableName": "Widgets", "Item": {"pk": {"S": "a"}}}},
                    {"Put": {"TableName": "Missing", "Item": {"pk": {"S": "b"}}}},
                ]
            }),
        );
        let _ = svc.transact_write_items(&req);

        let accts = state.read();
        let s = accts.get("123456789012").unwrap();
        let table = s.tables.get("Widgets").unwrap();
        assert_eq!(
            table.items.len(),
            0,
            "the Put on Widgets must not commit when a sibling table is missing"
        );
    }

    #[tokio::test]
    async fn execute_transaction_emits_stream_record_per_write() {
        let state = make_state();
        seed_table_with_stream(&state, "Widgets");
        let svc = DynamoDbService::new(state.clone());

        let req = req_for(
            "ExecuteTransaction",
            json!({
                "TransactStatements": [
                    {"Statement": "INSERT INTO \"Widgets\" VALUE {'pk': 'a'}"},
                    {"Statement": "INSERT INTO \"Widgets\" VALUE {'pk': 'b'}"},
                ]
            }),
        );
        let resp = svc.execute_transaction(&req).unwrap();
        assert_eq!(resp.status, http::StatusCode::OK);

        let accts = state.read();
        let s = accts.get("123456789012").unwrap();
        let table = s.tables.get("Widgets").unwrap();
        assert_eq!(table.items.len(), 2);
        assert_eq!(
            table.stream_records.read().len(),
            2,
            "each PartiQL INSERT must emit one stream record"
        );
    }

    #[tokio::test]
    async fn execute_transaction_reverts_on_mid_batch_failure() {
        let state = make_state();
        seed_table_with_stream(&state, "Widgets");
        let svc = DynamoDbService::new(state.clone());

        // First INSERT succeeds, second targets a missing table.
        let req = req_for(
            "ExecuteTransaction",
            json!({
                "TransactStatements": [
                    {"Statement": "INSERT INTO \"Widgets\" VALUE {'pk': 'a'}"},
                    {"Statement": "INSERT INTO \"Missing\" VALUE {'pk': 'b'}"},
                ]
            }),
        );
        let resp = svc.execute_transaction(&req).unwrap();
        assert_eq!(resp.status, http::StatusCode::BAD_REQUEST);

        let accts = state.read();
        let s = accts.get("123456789012").unwrap();
        let table = s.tables.get("Widgets").unwrap();
        assert_eq!(
            table.items.len(),
            0,
            "first INSERT must be reverted when the second statement fails"
        );
    }
}
