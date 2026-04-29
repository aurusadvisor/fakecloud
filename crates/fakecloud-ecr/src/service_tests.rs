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
