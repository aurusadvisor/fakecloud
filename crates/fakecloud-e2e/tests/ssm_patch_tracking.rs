mod helpers;

use std::collections::HashMap;

use aws_sdk_ssm::types::{
    DocumentMetadataEnum, DocumentReviewAction, DocumentReviewCommentSource,
    DocumentReviewCommentType, DocumentReviews, InventoryItem, OperatingSystem,
    PatchOrchestratorFilter, PatchProperty, Target,
};
use helpers::TestServer;

#[tokio::test]
async fn describe_patch_properties_returns_aws_classifications() {
    let server = TestServer::start().await;
    let client = server.ssm_client().await;

    let resp = client
        .describe_patch_properties()
        .operating_system(OperatingSystem::Windows)
        .property(PatchProperty::PatchClassification)
        .send()
        .await
        .unwrap();

    let props = resp.properties();
    assert!(!props.is_empty(), "expected windows classifications");
    assert!(props
        .iter()
        .any(|p| p.get("CLASSIFICATION").map(|s| s.as_str()) == Some("SecurityUpdates")));
}

#[tokio::test]
async fn describe_effective_patches_projects_baseline_approvals() {
    let server = TestServer::start().await;
    let client = server.ssm_client().await;

    let baseline = client
        .create_patch_baseline()
        .name("e2e-baseline")
        .operating_system(OperatingSystem::Windows)
        .approved_patches("KB-1001")
        .approved_patches("KB-1002")
        .approved_patches_compliance_level(aws_sdk_ssm::types::PatchComplianceLevel::Critical)
        .send()
        .await
        .unwrap();
    let baseline_id = baseline.baseline_id().unwrap().to_string();

    let resp = client
        .describe_effective_patches_for_patch_baseline()
        .baseline_id(baseline_id)
        .send()
        .await
        .unwrap();

    let effective = resp.effective_patches();
    assert_eq!(effective.len(), 2);
    let ids: Vec<&str> = effective
        .iter()
        .filter_map(|p| p.patch().and_then(|x| x.id()))
        .collect();
    assert!(ids.contains(&"KB-1001"));
    assert!(ids.contains(&"KB-1002"));
}

#[tokio::test]
async fn describe_instance_patches_surfaces_inventory_compliance() {
    let server = TestServer::start().await;
    let client = server.ssm_client().await;

    let mut row = HashMap::new();
    row.insert("Title".to_string(), "KB-9000 Critical update".to_string());
    row.insert("KBId".to_string(), "KB-9000".to_string());
    row.insert("Classification".to_string(), "SecurityUpdates".to_string());
    row.insert("Severity".to_string(), "Critical".to_string());
    row.insert("State".to_string(), "Installed".to_string());
    row.insert(
        "InstalledTime".to_string(),
        "2026-04-25T12:00:00Z".to_string(),
    );

    let item = InventoryItem::builder()
        .type_name("AWS:PatchCompliance")
        .schema_version("1.0")
        .capture_time("2026-04-25T12:00:00Z")
        .content(row)
        .build()
        .unwrap();

    client
        .put_inventory()
        .instance_id("i-e2etest1234567890")
        .items(item)
        .send()
        .await
        .unwrap();

    let resp = client
        .describe_instance_patches()
        .instance_id("i-e2etest1234567890")
        .send()
        .await
        .unwrap();

    let patches = resp.patches();
    assert_eq!(patches.len(), 1);
    assert_eq!(patches[0].kb_id(), "KB-9000");
    assert_eq!(patches[0].classification(), "SecurityUpdates");
    assert_eq!(patches[0].severity(), "Critical");
}

#[tokio::test]
async fn describe_instance_patch_states_uses_inventory_summary() {
    let server = TestServer::start().await;
    let client = server.ssm_client().await;

    let mut row = HashMap::new();
    row.insert(
        "BaselineId".to_string(),
        "pb-summary-test-12345".to_string(),
    );
    row.insert("PatchGroup".to_string(), "prod".to_string());
    row.insert("InstalledCount".to_string(), "12".to_string());
    row.insert("MissingCount".to_string(), "3".to_string());
    row.insert("FailedCount".to_string(), "1".to_string());
    row.insert("Operation".to_string(), "Scan".to_string());
    row.insert(
        "OperationStartTime".to_string(),
        "2026-04-25T11:00:00Z".to_string(),
    );
    row.insert(
        "OperationEndTime".to_string(),
        "2026-04-25T11:05:00Z".to_string(),
    );

    let item = InventoryItem::builder()
        .type_name("AWS:PatchSummary")
        .schema_version("1.0")
        .capture_time("2026-04-25T11:05:00Z")
        .content(row)
        .build()
        .unwrap();

    client
        .put_inventory()
        .instance_id("i-summary-test-1234")
        .items(item)
        .send()
        .await
        .unwrap();

    let resp = client
        .describe_instance_patch_states()
        .instance_ids("i-summary-test-1234")
        .send()
        .await
        .unwrap();

    let states = resp.instance_patch_states();
    assert_eq!(states.len(), 1);
    assert_eq!(states[0].installed_count(), 12);
    assert_eq!(states[0].missing_count(), 3);
    assert_eq!(states[0].failed_count(), 1);
    assert_eq!(states[0].patch_group(), "prod");
}

#[tokio::test]
async fn document_metadata_history_round_trip() {
    let server = TestServer::start().await;
    let client = server.ssm_client().await;

    client
        .create_document()
        .name("e2e-review-doc")
        .content(r#"{"schemaVersion":"2.2","mainSteps":[]}"#)
        .document_type(aws_sdk_ssm::types::DocumentType::Command)
        .send()
        .await
        .unwrap();

    let comment = DocumentReviewCommentSource::builder()
        .r#type(DocumentReviewCommentType::Comment)
        .content("approved by e2e")
        .build();

    let reviews = DocumentReviews::builder()
        .action(DocumentReviewAction::Approve)
        .comment(comment)
        .build()
        .unwrap();

    client
        .update_document_metadata()
        .name("e2e-review-doc")
        .document_reviews(reviews)
        .send()
        .await
        .unwrap();

    let resp = client
        .list_document_metadata_history()
        .name("e2e-review-doc")
        .metadata(DocumentMetadataEnum::DocumentReviews)
        .send()
        .await
        .unwrap();

    let metadata = resp.metadata().unwrap();
    let responses = metadata.reviewer_response();
    assert_eq!(responses.len(), 1);
    assert_eq!(responses[0].review_status().unwrap().as_str(), "APPROVED");
    let comments = responses[0].comment();
    assert_eq!(comments.len(), 1);
    assert_eq!(comments[0].content().unwrap(), "approved by e2e");
}

#[tokio::test]
async fn start_associations_once_marks_pending() {
    let server = TestServer::start().await;
    let client = server.ssm_client().await;

    client
        .create_document()
        .name("e2e-assoc-doc")
        .content(r#"{"schemaVersion":"2.2","mainSteps":[]}"#)
        .document_type(aws_sdk_ssm::types::DocumentType::Command)
        .send()
        .await
        .unwrap();

    let assoc = client
        .create_association()
        .name("e2e-assoc-doc")
        .targets(
            Target::builder()
                .key("InstanceIds")
                .values("i-assoc1234")
                .build(),
        )
        .send()
        .await
        .unwrap();
    let assoc_id = assoc
        .association_description()
        .and_then(|a| a.association_id())
        .unwrap()
        .to_string();

    client
        .start_associations_once()
        .association_ids(assoc_id.clone())
        .send()
        .await
        .unwrap();

    let resp = client
        .describe_association()
        .association_id(assoc_id)
        .send()
        .await
        .unwrap();

    let desc = resp.association_description().unwrap();
    assert_eq!(desc.status().unwrap().name().as_str(), "Pending");
    assert!(desc.last_execution_date().is_some());
}

#[tokio::test]
async fn describe_patch_baselines_filter_unknown_keys_passthrough() {
    let server = TestServer::start().await;
    let client = server.ssm_client().await;

    client
        .create_patch_baseline()
        .name("e2e-filter-baseline")
        .operating_system(OperatingSystem::AmazonLinux2)
        .send()
        .await
        .unwrap();

    let resp = client
        .describe_patch_baselines()
        .filters(
            PatchOrchestratorFilter::builder()
                .key("UnknownKey")
                .values("ignored")
                .build(),
        )
        .send()
        .await
        .unwrap();

    assert!(!resp.baseline_identities().is_empty());
}
