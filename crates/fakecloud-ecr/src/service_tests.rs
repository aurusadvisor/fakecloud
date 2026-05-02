use super::validate_repository_name;

#[track_caller]
fn ok(n: &str) {
    validate_repository_name(n).unwrap_or_else(|_| panic!("expected '{n}' to validate"));
}
#[track_caller]
fn bad(n: &str) {
    assert!(
        validate_repository_name(n).is_err(),
        "expected '{n}' to be rejected",
    );
}

#[test]
fn accepts_valid_names() {
    ok("foo");
    ok("foo-bar");
    ok("foo.bar");
    ok("foo_bar");
    ok("foo/bar");
    ok("team/svc");
    ok("a/b/c");
    ok("foo123/bar-baz.qux_q");
}

#[test]
fn rejects_invalid_names() {
    bad("");
    bad("a");
    bad("/foo");
    bad("foo/");
    bad("foo//bar");
    bad("-foo");
    bad("foo-");
    bad("foo--bar");
    bad("foo..bar");
    bad("foo__bar");
    bad("Foo");
    bad("foo bar");
    bad("foo!");
}

// ── Lifecycle policy evaluator ─────────────────────────────────
use super::{evaluate_lifecycle_policy, wildcard_match};
use crate::state::{Image, Repository};
use chrono::Utc;

fn repo_with_images(entries: &[(&str, &[&str], i64)]) -> Repository {
    // entries: (digest, tags, minutes_ago_pushed)
    let mut r = Repository::new("test-repo", "arn".into(), "123", "http://localhost");
    for (digest, tags, minutes_ago) in entries {
        let pushed = Utc::now() - chrono::Duration::minutes(*minutes_ago);
        r.images.insert(
            (*digest).to_string(),
            Image {
                image_digest: (*digest).to_string(),
                image_manifest: String::new(),
                image_manifest_media_type: String::new(),
                artifact_media_type: None,
                image_size_in_bytes: 0,
                image_pushed_at: pushed,
                last_recorded_pull_time: None,
            },
        );
        for t in *tags {
            r.image_tags.insert((*t).to_string(), (*digest).to_string());
        }
    }
    r
}

#[test]
fn lifecycle_count_more_than_tagged() {
    // Five tagged images; rule says keep newest 2, prune 3.
    let r = repo_with_images(&[
        ("sha256:a", &["v1"], 50),
        ("sha256:b", &["v2"], 40),
        ("sha256:c", &["v3"], 30),
        ("sha256:d", &["v4"], 20),
        ("sha256:e", &["v5"], 10),
    ]);
    let policy = r#"{"rules":[{
        "rulePriority": 1,
        "selection": {"tagStatus":"tagged","countType":"imageCountMoreThan","countNumber":2}
    }]}"#;
    let prune = evaluate_lifecycle_policy(&r, policy);
    assert_eq!(prune.len(), 3);
    assert!(prune.contains(&"sha256:a".to_string()));
    assert!(prune.contains(&"sha256:b".to_string()));
    assert!(prune.contains(&"sha256:c".to_string()));
}

#[test]
fn lifecycle_untagged_only() {
    let r = repo_with_images(&[("sha256:tagged", &["v1"], 60), ("sha256:untag", &[], 30)]);
    let policy = r#"{"rules":[{
        "rulePriority": 1,
        "selection": {"tagStatus":"untagged","countType":"imageCountMoreThan","countNumber":0}
    }]}"#;
    let prune = evaluate_lifecycle_policy(&r, policy);
    assert_eq!(prune, vec!["sha256:untag".to_string()]);
}

#[test]
fn lifecycle_tag_prefix_list() {
    let r = repo_with_images(&[
        ("sha256:a", &["dev-1"], 60),
        ("sha256:b", &["dev-2"], 50),
        ("sha256:c", &["prod-1"], 40),
        ("sha256:d", &["prod-2"], 30),
    ]);
    // Keep newest 1 among dev-*, prune the rest; leave prod-* alone.
    let policy = r#"{"rules":[{
        "rulePriority": 1,
        "selection": {
            "tagStatus":"tagged",
            "tagPrefixList":["dev-"],
            "countType":"imageCountMoreThan",
            "countNumber":1
        }
    }]}"#;
    let prune = evaluate_lifecycle_policy(&r, policy);
    assert_eq!(prune, vec!["sha256:a".to_string()]);
}

#[test]
fn lifecycle_tag_pattern_list_wildcards() {
    let r = repo_with_images(&[
        ("sha256:a", &["release-2024-01"], 60),
        ("sha256:b", &["release-2024-02"], 50),
        ("sha256:c", &["hotfix-2024-02"], 40),
    ]);
    // Match only `release-*`; prune all of them (countNumber=0).
    let policy = r#"{"rules":[{
        "rulePriority": 1,
        "selection": {
            "tagStatus":"tagged",
            "tagPatternList":["release-*"],
            "countType":"imageCountMoreThan",
            "countNumber":0
        }
    }]}"#;
    let prune = evaluate_lifecycle_policy(&r, policy);
    assert_eq!(prune.len(), 2);
    assert!(prune.contains(&"sha256:a".to_string()));
    assert!(prune.contains(&"sha256:b".to_string()));
    assert!(!prune.contains(&"sha256:c".to_string()));
}

#[test]
fn lifecycle_since_image_pushed_days() {
    let r = repo_with_images(&[
        ("sha256:old", &["v1"], 60 * 24 * 10), // 10 days ago
        ("sha256:new", &["v2"], 60 * 24),      // 1 day ago
    ]);
    let policy = r#"{"rules":[{
        "rulePriority": 1,
        "selection": {
            "tagStatus":"any",
            "countType":"sinceImagePushed",
            "countUnit":"days",
            "countNumber":5
        }
    }]}"#;
    let prune = evaluate_lifecycle_policy(&r, policy);
    assert_eq!(prune, vec!["sha256:old".to_string()]);
}

#[test]
fn lifecycle_rule_priority_order() {
    // Priority 1 keeps newest 2 tagged; priority 2 then prunes all
    // remaining tagged > 1 day old. Priority 1 runs first, then 2
    // sees fewer candidates.
    let r = repo_with_images(&[
        ("sha256:a", &["v1"], 60 * 24 * 10),
        ("sha256:b", &["v2"], 60 * 24 * 5),
        ("sha256:c", &["v3"], 60 * 24 * 2),
        ("sha256:d", &["v4"], 60 * 24),
    ]);
    let policy = r#"{"rules":[
        {"rulePriority": 2,
         "selection": {"tagStatus":"any","countType":"sinceImagePushed","countUnit":"days","countNumber":3}},
        {"rulePriority": 1,
         "selection": {"tagStatus":"tagged","countType":"imageCountMoreThan","countNumber":2}}
    ]}"#;
    let prune: std::collections::BTreeSet<String> =
        evaluate_lifecycle_policy(&r, policy).into_iter().collect();
    // Priority 1 (runs first): prunes a + b (keeping newest 2 = c, d).
    // Priority 2: c and d are both < 3 days -> survives.
    assert!(prune.contains("sha256:a"));
    assert!(prune.contains("sha256:b"));
}

#[test]
fn wildcard_match_basics() {
    assert!(wildcard_match("release-*", "release-2024"));
    assert!(wildcard_match("*-stable", "v1-stable"));
    assert!(wildcard_match("a*b*c", "a-something-b-more-c"));
    assert!(wildcard_match("*", "anything"));
    assert!(wildcard_match("exact", "exact"));

    assert!(!wildcard_match("release-*", "rev-2024"));
    assert!(!wildcard_match("*-stable", "v1-beta"));
    assert!(!wildcard_match("exact", "exactly"));
    assert!(!wildcard_match("a*b*c", "a-b"));
}

// ── Registry-level scan-on-push fallback ───────────────────────
use super::{registry_filter_matches, registry_scan_on_push_matches};
use crate::state::{
    RegistryScanningConfiguration, RegistryScanningRule, RepositoryFilter as RegRepositoryFilter,
};

fn rule(freq: &str, filters: Vec<(&str, &str)>) -> RegistryScanningRule {
    RegistryScanningRule {
        scan_frequency: freq.to_string(),
        repository_filters: filters
            .into_iter()
            .map(|(f, t)| RegRepositoryFilter {
                filter: f.to_string(),
                filter_type: t.to_string(),
            })
            .collect(),
    }
}

#[test]
fn registry_scan_matches_when_filter_wildcards_repo() {
    let cfg = RegistryScanningConfiguration {
        scan_type: "BASIC".to_string(),
        rules: vec![rule("SCAN_ON_PUSH", vec![("prod-*", "WILDCARD")])],
    };
    assert!(registry_scan_on_push_matches(&cfg, "prod-api"));
    assert!(!registry_scan_on_push_matches(&cfg, "dev-api"));
}

#[test]
fn registry_scan_matches_when_filter_list_empty() {
    let cfg = RegistryScanningConfiguration {
        scan_type: "BASIC".to_string(),
        rules: vec![rule("SCAN_ON_PUSH", vec![])],
    };
    assert!(registry_scan_on_push_matches(&cfg, "anything"));
}

#[test]
fn registry_scan_skips_continuous_scan_frequency() {
    let cfg = RegistryScanningConfiguration {
        scan_type: "ENHANCED".to_string(),
        rules: vec![rule("CONTINUOUS_SCAN", vec![("*", "WILDCARD")])],
    };
    assert!(!registry_scan_on_push_matches(&cfg, "x"));
}

#[test]
fn registry_filter_rejects_unknown_filter_type() {
    let f = RegRepositoryFilter {
        filter: "x".to_string(),
        filter_type: "REGEX".to_string(),
    };
    assert!(!registry_filter_matches(&f, "x"));
}

#[test]
fn registry_scan_no_rules_no_match() {
    let cfg = RegistryScanningConfiguration::default();
    assert!(!registry_scan_on_push_matches(&cfg, "x"));
}

#[test]
fn repository_filters_match_returns_true_on_empty_list() {
    use super::repository_filters_match;
    assert!(repository_filters_match(&[], "any-repo"));
}

#[test]
fn repository_filters_match_honours_wildcard() {
    use super::repository_filters_match;
    use crate::state::RepositoryFilter;
    let filters = vec![RepositoryFilter {
        filter: "team-a/*".to_string(),
        filter_type: "WILDCARD".to_string(),
    }];
    assert!(repository_filters_match(&filters, "team-a/svc"));
    assert!(!repository_filters_match(&filters, "team-b/svc"));
}

#[test]
fn replicate_image_copies_to_destination_account() {
    use super::EcrService;
    use crate::state::{
        EcrState, Image, ReplicationConfiguration, ReplicationDestination, ReplicationRule,
        Repository,
    };
    use fakecloud_core::multi_account::MultiAccountState;
    use parking_lot::RwLock;
    use std::sync::Arc;

    const SOURCE: &str = "111111111111";
    const TARGET: &str = "222222222222";

    let mut mas: MultiAccountState<EcrState> =
        MultiAccountState::new(SOURCE, "us-east-1", "http://fakecloud:4566");
    let source_state = mas.get_or_create(SOURCE);
    source_state.replication_configuration = Some(ReplicationConfiguration {
        rules: vec![ReplicationRule {
            destinations: vec![ReplicationDestination {
                region: "us-west-2".to_string(),
                registry_id: TARGET.to_string(),
            }],
            repository_filters: Vec::new(),
        }],
    });
    let arn = source_state.repository_arn("app");
    let mut repo = Repository::new("app", arn, SOURCE, "fakecloud:4566");
    repo.images.insert(
        "sha256:abc".to_string(),
        Image {
            image_digest: "sha256:abc".to_string(),
            image_manifest: "{\"mediaType\":\"x\"}".to_string(),
            image_manifest_media_type: "application/vnd.oci.image.manifest.v1+json".to_string(),
            artifact_media_type: None,
            image_size_in_bytes: 0,
            image_pushed_at: chrono::Utc::now(),
            last_recorded_pull_time: None,
        },
    );
    source_state.repositories.insert("app".to_string(), repo);

    let state: crate::state::SharedEcrState = Arc::new(RwLock::new(mas));
    let svc = EcrService::new(state.clone());
    svc.replicate_image(SOURCE, "app", "sha256:abc");

    let accounts = state.read();
    let target_state = accounts.get(TARGET).expect("target account created");
    let target_repo = target_state
        .repositories
        .get("app")
        .expect("target repo provisioned");
    assert!(target_repo.images.contains_key("sha256:abc"));

    let source_state = accounts.get(SOURCE).expect("source account intact");
    let source_repo = source_state.repositories.get("app").unwrap();
    let statuses = source_repo
        .replication_statuses
        .get("sha256:abc")
        .expect("status entry recorded");
    assert_eq!(statuses.len(), 1);
    assert_eq!(statuses[0].status, "COMPLETE");
    assert_eq!(statuses[0].registry_id, TARGET);
}
