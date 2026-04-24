//! ECR pull-through cache real proxy. Configures a rule pointing at
//! `public.ecr.aws` (no-auth upstream), fetches a manifest through
//! fakecloud's OCI v2, and asserts that the local repo is populated
//! afterwards so the next pull hits local cache.

mod helpers;

use aws_sdk_ecr::types::PullThroughCacheRule;
use helpers::TestServer;

fn network_available() -> bool {
    // Treat `FAKECLOUD_SKIP_NETWORK=1` as an opt-out for offline CI.
    std::env::var("FAKECLOUD_SKIP_NETWORK").is_err()
}

#[tokio::test]
async fn pull_through_proxies_manifest_from_public_ecr() {
    if !network_available() {
        eprintln!("skipping: FAKECLOUD_SKIP_NETWORK set");
        return;
    }

    let server = TestServer::start().await;
    let ecr = server.ecr_client().await;

    ecr.create_pull_through_cache_rule()
        .ecr_repository_prefix("ecr-public")
        .upstream_registry_url("https://public.ecr.aws")
        .send()
        .await
        .expect("create_pull_through_cache_rule");

    // Sanity: rule survives round-trip.
    let rules = ecr
        .describe_pull_through_cache_rules()
        .send()
        .await
        .unwrap();
    let matched: Vec<&PullThroughCacheRule> = rules
        .pull_through_cache_rules()
        .iter()
        .filter(|r| r.ecr_repository_prefix() == Some("ecr-public"))
        .collect();
    assert_eq!(matched.len(), 1);

    // Fetch a well-known small manifest (amazonlinux:latest index) via
    // fakecloud's OCI v2. The path segment after `ecr-public/` is
    // what proxies upstream — `amazonlinux/amazonlinux/manifests/...`
    // goes to `https://public.ecr.aws/amazonlinux/amazonlinux/manifests/...`
    let http = reqwest::Client::new();
    let url = format!(
        "{}/v2/ecr-public/amazonlinux/amazonlinux/manifests/latest",
        server.endpoint()
    );
    let resp = http
        .get(&url)
        .header(
            "Authorization",
            format!("Basic {}", base64::engine::general_purpose::STANDARD.encode("AWS:test")),
        )
        .header(
            "Accept",
            "application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.index.v1+json",
        )
        .send()
        .await
        .expect("fakecloud manifest GET");
    assert!(
        resp.status().is_success(),
        "expected 2xx; got {}",
        resp.status()
    );
    let digest = resp
        .headers()
        .get("docker-content-digest")
        .and_then(|v| v.to_str().ok())
        .expect("Docker-Content-Digest header")
        .to_string();
    assert!(digest.starts_with("sha256:"));

    // Local repo should exist now, auto-created by the proxy.
    let repos = ecr
        .describe_repositories()
        .repository_names("ecr-public/amazonlinux/amazonlinux")
        .send()
        .await
        .expect("describe_repositories after proxy");
    assert_eq!(
        repos.repositories().len(),
        1,
        "pull-through proxy should have auto-created the local repo"
    );

    // Second request for the same manifest should hit the local cache —
    // assert the stored image shows up through the AWS JSON API.
    let images = ecr
        .describe_images()
        .repository_name("ecr-public/amazonlinux/amazonlinux")
        .send()
        .await
        .expect("describe_images after proxy");
    assert!(
        images
            .image_details()
            .iter()
            .any(|d| d.image_digest() == Some(&digest)),
        "cached manifest digest missing from DescribeImages"
    );
}

use base64::Engine;
