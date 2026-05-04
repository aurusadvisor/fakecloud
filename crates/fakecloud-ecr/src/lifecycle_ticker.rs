//! Periodic re-evaluation of repository lifecycle policies.
//!
//! `PutLifecyclePolicy` runs the policy synchronously once at write
//! time. AWS ECR also re-runs lifecycle rules on a recurring schedule
//! so that `sinceImagePushed` time-based selections eventually evict
//! aging images even when no new push triggers an evaluation. This
//! ticker provides that re-run loop: every `interval` it walks all
//! repositories that have a lifecycle policy, applies the prune set,
//! and stamps `lifecycle_policy_last_evaluated_at`.
//!
//! When no repository has a lifecycle policy set the tick is a cheap
//! read-only scan of `state` and exits without taking the write lock,
//! so the loop costs almost nothing in idle setups.
//!
//! The ticker is wired up at server startup in `fakecloud-server` via
//! `tokio::spawn(LifecycleTicker::new(state).run())`.
use std::time::Duration;

use chrono::Utc;

use crate::service::evaluate_lifecycle_policy;
use crate::state::SharedEcrState;

/// Default tick interval. AWS itself doesn't publish a guaranteed
/// re-eval cadence; 5 minutes is a balance between picking up
/// `sinceImagePushed` evictions promptly and not burning CPU walking
/// idle accounts.
pub const DEFAULT_TICK_INTERVAL: Duration = Duration::from_secs(300);

/// Background task that periodically re-applies lifecycle policies.
pub struct LifecycleTicker {
    state: SharedEcrState,
    interval: Duration,
}

impl LifecycleTicker {
    pub fn new(state: SharedEcrState) -> Self {
        Self {
            state,
            interval: DEFAULT_TICK_INTERVAL,
        }
    }

    /// Override the tick interval. Tests use a tiny value; production
    /// uses the default.
    pub fn with_interval(mut self, interval: Duration) -> Self {
        self.interval = interval;
        self
    }

    pub async fn run(self) {
        let mut ticker = tokio::time::interval(self.interval);
        // First tick fires immediately by default — skip it so we
        // don't double-evaluate right after server start (the
        // synchronous PutLifecyclePolicy path already evaluated).
        ticker.tick().await;
        loop {
            ticker.tick().await;
            tick_once(&self.state);
        }
    }
}

/// Single pass over all accounts/repositories. Re-evaluates each
/// lifecycle policy and applies the resulting prune set. Cheap when
/// no policies are set: a read-only scan that bails before touching
/// the write lock.
pub fn tick_once(state: &SharedEcrState) {
    // Collect (account_id, repo_name, policy) under the read lock so
    // we don't hold the writer while parsing JSON. Doubles as the
    // cheap precheck — when no repo has a policy, `plans` is empty
    // and we bail before touching the write lock.
    let plans: Vec<(String, String, String)> = {
        let accounts = state.read();
        let mut out: Vec<(String, String, String)> = Vec::new();
        for (acct, s) in accounts.iter() {
            for (name, repo) in s.repositories.iter() {
                if let Some(policy) = repo.lifecycle_policy.as_ref() {
                    out.push((acct.to_string(), name.clone(), policy.clone()));
                }
            }
        }
        out
    };

    if plans.is_empty() {
        return;
    }

    let mut accounts = state.write();
    let now = Utc::now();
    for (account, name, policy) in plans {
        let Some(s) = accounts.get_mut(&account) else {
            continue;
        };
        let Some(repo) = s.repositories.get_mut(&name) else {
            continue;
        };
        let prune = evaluate_lifecycle_policy(repo, &policy);
        if !prune.is_empty() {
            tracing::info!(
                repository = %name,
                account = %account,
                count = prune.len(),
                "ECR lifecycle: pruning expired images on tick"
            );
            for digest in &prune {
                repo.images.remove(digest);
                repo.image_tags.retain(|_, d| d != digest);
            }
        }
        repo.lifecycle_policy_last_evaluated_at = Some(now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{EcrState, Image, Repository};
    use chrono::Duration as ChronoDuration;
    use fakecloud_core::multi_account::MultiAccountState;
    use parking_lot::RwLock;
    use std::sync::Arc;

    const ACCOUNT: &str = "111111111111";

    fn shared_state_with_repo(repo: Repository) -> SharedEcrState {
        let mut mas: MultiAccountState<EcrState> =
            MultiAccountState::new(ACCOUNT, "us-east-1", "http://fakecloud:4566");
        let s = mas.get_or_create(ACCOUNT);
        s.repositories.insert(repo.repository_name.clone(), repo);
        Arc::new(RwLock::new(mas))
    }

    fn make_repo_with_old_image() -> Repository {
        let arn = format!("arn:aws:ecr:us-east-1:{ACCOUNT}:repository/svc");
        let mut repo = Repository::new("svc", arn, ACCOUNT, "fakecloud:4566");
        repo.images.insert(
            "sha256:old".to_string(),
            Image {
                image_digest: "sha256:old".to_string(),
                image_manifest: String::new(),
                image_manifest_media_type: String::new(),
                artifact_media_type: None,
                image_size_in_bytes: 0,
                // Pushed 30 days ago.
                image_pushed_at: Utc::now() - ChronoDuration::days(30),
                last_recorded_pull_time: None,
                image_status: "ACTIVE".to_string(),
                last_archived_at: None,
                last_activated_at: None,
                last_in_use_at: None,
                in_use_count: 0,
            },
        );
        repo.image_tags
            .insert("v1".to_string(), "sha256:old".to_string());
        repo
    }

    #[test]
    fn tick_once_no_policy_is_cheap_and_noop() {
        let state = shared_state_with_repo(make_repo_with_old_image());
        // No policy set -> no last_evaluated_at, no image removal.
        tick_once(&state);
        let accounts = state.read();
        let repo = accounts
            .get(ACCOUNT)
            .unwrap()
            .repositories
            .get("svc")
            .unwrap();
        assert!(repo.lifecycle_policy_last_evaluated_at.is_none());
        assert_eq!(repo.images.len(), 1);
    }

    #[test]
    fn tick_once_prunes_and_stamps_last_evaluated_at() {
        let mut repo = make_repo_with_old_image();
        // Policy: prune images older than 7 days.
        repo.lifecycle_policy = Some(
            r#"{"rules":[{
                "rulePriority":1,
                "selection":{
                    "tagStatus":"any",
                    "countType":"sinceImagePushed",
                    "countUnit":"days",
                    "countNumber":7
                }
            }]}"#
                .to_string(),
        );
        let state = shared_state_with_repo(repo);
        tick_once(&state);
        let accounts = state.read();
        let repo = accounts
            .get(ACCOUNT)
            .unwrap()
            .repositories
            .get("svc")
            .unwrap();
        assert!(
            repo.lifecycle_policy_last_evaluated_at.is_some(),
            "tick should stamp last_evaluated_at"
        );
        assert!(
            repo.images.is_empty(),
            "old image should have been pruned by tick"
        );
        assert!(
            repo.image_tags.is_empty(),
            "tags pointing at pruned image should be gone"
        );
    }

    #[test]
    fn tick_once_updates_timestamp_even_when_nothing_to_prune() {
        let mut repo = make_repo_with_old_image();
        // Policy that matches but keeps the image (countNumber=10
        // covers the only image).
        repo.lifecycle_policy = Some(
            r#"{"rules":[{
                "rulePriority":1,
                "selection":{
                    "tagStatus":"tagged",
                    "countType":"imageCountMoreThan",
                    "countNumber":10
                }
            }]}"#
                .to_string(),
        );
        let state = shared_state_with_repo(repo);
        tick_once(&state);
        let accounts = state.read();
        let repo = accounts
            .get(ACCOUNT)
            .unwrap()
            .repositories
            .get("svc")
            .unwrap();
        assert!(repo.lifecycle_policy_last_evaluated_at.is_some());
        assert_eq!(repo.images.len(), 1);
    }
}
