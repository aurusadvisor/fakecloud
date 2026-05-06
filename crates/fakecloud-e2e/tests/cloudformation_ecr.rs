//! CloudFormation provisioner for AWS::ECR::Repository.

mod helpers;

use aws_sdk_cloudformation::types::{Capability, OnFailure};
use helpers::TestServer;

const TEMPLATE: &str = r#"{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "AppRepo": {
      "Type": "AWS::ECR::Repository",
      "Properties": {
        "RepositoryName": "cfn-app",
        "ImageTagMutability": "IMMUTABLE",
        "ImageScanningConfiguration": {"ScanOnPush": true},
        "EncryptionConfiguration": {"EncryptionType": "AES256"},
        "RepositoryPolicyText": {
          "Version": "2012-10-17",
          "Statement": [{
            "Sid": "Pull",
            "Effect": "Allow",
            "Principal": {"AWS": "*"},
            "Action": ["ecr:GetDownloadUrlForLayer", "ecr:BatchGetImage"]
          }]
        },
        "LifecyclePolicy": {
          "LifecyclePolicyText": "{\"rules\":[{\"rulePriority\":1,\"description\":\"keep latest 10\",\"selection\":{\"tagStatus\":\"any\",\"countType\":\"imageCountMoreThan\",\"countNumber\":10},\"action\":{\"type\":\"expire\"}}]}"
        }
      }
    }
  },
  "Outputs": {
    "RepoName": {"Value": {"Ref": "AppRepo"}},
    "RepoArn": {"Value": {"Fn::GetAtt": ["AppRepo", "Arn"]}},
    "RepoUri": {"Value": {"Fn::GetAtt": ["AppRepo", "RepositoryUri"]}}
  }
}"#;

#[tokio::test]
async fn cfn_provisions_and_deletes_ecr_repository() {
    let server = TestServer::start().await;
    let cfn = server.cloudformation_client().await;
    let ecr = server.ecr_client().await;

    cfn.create_stack()
        .stack_name("ecr-stack")
        .template_body(TEMPLATE)
        .capabilities(Capability::CapabilityIam)
        .on_failure(OnFailure::Rollback)
        .send()
        .await
        .expect("create_stack");

    let described = cfn
        .describe_stacks()
        .stack_name("ecr-stack")
        .send()
        .await
        .expect("describe_stacks");
    let stack = described.stacks().first().expect("stack present");
    assert_eq!(stack.stack_status().unwrap().as_str(), "CREATE_COMPLETE");

    let mut name = None;
    let mut arn = None;
    let mut uri = None;
    for o in stack.outputs() {
        match o.output_key() {
            Some("RepoName") => name = o.output_value().map(|s| s.to_string()),
            Some("RepoArn") => arn = o.output_value().map(|s| s.to_string()),
            Some("RepoUri") => uri = o.output_value().map(|s| s.to_string()),
            _ => {}
        }
    }
    let name = name.expect("RepoName output");
    let arn = arn.expect("RepoArn output");
    let uri = uri.expect("RepoUri output");
    assert_eq!(name, "cfn-app");
    assert!(arn.starts_with("arn:aws:ecr:") && arn.ends_with(":repository/cfn-app"));
    assert!(uri.ends_with("/cfn-app"));

    let described_repo = ecr
        .describe_repositories()
        .repository_names(&name)
        .send()
        .await
        .expect("describe_repositories");
    let repo = described_repo.repositories().first().expect("repo present");
    assert_eq!(repo.repository_name(), Some(name.as_str()));
    assert_eq!(
        repo.image_tag_mutability().map(|m| m.as_str()),
        Some("IMMUTABLE")
    );
    assert_eq!(
        repo.image_scanning_configuration()
            .map(|c| c.scan_on_push()),
        Some(true)
    );

    let policy = ecr
        .get_repository_policy()
        .repository_name(&name)
        .send()
        .await
        .expect("get_repository_policy");
    assert!(
        policy
            .policy_text()
            .map(|s| s.contains("ecr:GetDownloadUrlForLayer"))
            .unwrap_or(false),
        "policy text should round-trip the inline policy"
    );

    let lifecycle = ecr
        .get_lifecycle_policy()
        .repository_name(&name)
        .send()
        .await
        .expect("get_lifecycle_policy");
    assert!(
        lifecycle
            .lifecycle_policy_text()
            .map(|s| s.contains("imageCountMoreThan"))
            .unwrap_or(false),
        "lifecycle policy text should round-trip"
    );

    cfn.delete_stack()
        .stack_name("ecr-stack")
        .send()
        .await
        .expect("delete_stack");

    let after = ecr
        .describe_repositories()
        .repository_names(&name)
        .send()
        .await;
    assert!(
        after.is_err(),
        "repository should be gone after stack deletion"
    );
}

const POLICY_TEMPLATE: &str = r#"{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "Repo": {
      "Type": "AWS::ECR::Repository",
      "Properties": {"RepositoryName": "ecr-cfn-policy-repo"}
    },
    "RepoPolicy": {
      "Type": "AWS::ECR::RepositoryPolicy",
      "Properties": {
        "RepositoryName": {"Ref": "Repo"},
        "PolicyText": {
          "Version": "2012-10-17",
          "Statement": [{
            "Sid": "AllowPull",
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
            "Action": ["ecr:GetDownloadUrlForLayer", "ecr:BatchGetImage"]
          }]
        }
      }
    },
    "RegPolicy": {
      "Type": "AWS::ECR::RegistryPolicy",
      "Properties": {
        "PolicyText": {
          "Version": "2012-10-17",
          "Statement": [{
            "Sid": "ReplicationAccess",
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::222222222222:root"},
            "Action": ["ecr:CreateRepository", "ecr:ReplicateImage"],
            "Resource": "*"
          }]
        }
      }
    },
    "Replication": {
      "Type": "AWS::ECR::ReplicationConfiguration",
      "Properties": {
        "ReplicationConfiguration": {
          "Rules": [{
            "Destinations": [{
              "Region": "us-west-2",
              "RegistryId": "222222222222"
            }],
            "RepositoryFilters": [{
              "Filter": "ecr-cfn-policy-",
              "FilterType": "PREFIX_MATCH"
            }]
          }]
        }
      }
    },
    "PtCache": {
      "Type": "AWS::ECR::PullThroughCacheRule",
      "Properties": {
        "EcrRepositoryPrefix": "ecr-public",
        "UpstreamRegistryUrl": "public.ecr.aws"
      }
    }
  }
}"#;

#[tokio::test]
async fn cfn_provisions_ecr_policies_and_registry_config() {
    let server = TestServer::start().await;
    let cfn = server.cloudformation_client().await;
    let ecr = aws_sdk_ecr::Client::new(&server.aws_config().await);

    cfn.create_stack()
        .stack_name("ecr-policy-stack")
        .template_body(POLICY_TEMPLATE)
        .send()
        .await
        .expect("create_stack");

    let described = cfn
        .describe_stacks()
        .stack_name("ecr-policy-stack")
        .send()
        .await
        .expect("describe_stacks");
    assert_eq!(
        described
            .stacks()
            .first()
            .unwrap()
            .stack_status()
            .unwrap()
            .as_str(),
        "CREATE_COMPLETE"
    );

    let repo_policy = ecr
        .get_repository_policy()
        .repository_name("ecr-cfn-policy-repo")
        .send()
        .await
        .expect("get_repository_policy");
    assert!(repo_policy
        .policy_text()
        .map(|s| s.contains("AllowPull"))
        .unwrap_or(false));

    let reg_policy = ecr
        .get_registry_policy()
        .send()
        .await
        .expect("get_registry_policy");
    assert!(reg_policy
        .policy_text()
        .map(|s| s.contains("ReplicationAccess"))
        .unwrap_or(false));

    let replication = ecr
        .describe_registry()
        .send()
        .await
        .expect("describe_registry");
    assert_eq!(
        replication
            .replication_configuration()
            .map(|c| c.rules().len()),
        Some(1)
    );

    let cache = ecr
        .describe_pull_through_cache_rules()
        .send()
        .await
        .expect("describe_pull_through_cache_rules");
    assert!(cache
        .pull_through_cache_rules()
        .iter()
        .any(|r| r.ecr_repository_prefix() == Some("ecr-public")));

    cfn.delete_stack()
        .stack_name("ecr-policy-stack")
        .send()
        .await
        .expect("delete_stack");

    let reg_after = ecr.get_registry_policy().send().await;
    assert!(reg_after.is_err(), "registry policy should be cleared");
}

const LIFECYCLE_TEMPLATE: &str = r#"{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "Repo": {
      "Type": "AWS::ECR::Repository",
      "Properties": {"RepositoryName": "ecr-cfn-lifecycle-repo"}
    },
    "Lifecycle": {
      "Type": "AWS::ECR::LifecyclePolicy",
      "Properties": {
        "RepositoryName": {"Ref": "Repo"},
        "LifecyclePolicyText": "{\"rules\":[{\"rulePriority\":1,\"description\":\"keep latest 5\",\"selection\":{\"tagStatus\":\"any\",\"countType\":\"imageCountMoreThan\",\"countNumber\":5},\"action\":{\"type\":\"expire\"}}]}"
      }
    }
  }
}"#;

#[tokio::test]
async fn cfn_provisions_standalone_ecr_lifecycle_policy() {
    let server = TestServer::start().await;
    let cfn = server.cloudformation_client().await;
    let ecr = server.ecr_client().await;

    cfn.create_stack()
        .stack_name("ecr-lifecycle-stack")
        .template_body(LIFECYCLE_TEMPLATE)
        .send()
        .await
        .expect("create_stack");

    let described = cfn
        .describe_stacks()
        .stack_name("ecr-lifecycle-stack")
        .send()
        .await
        .expect("describe_stacks");
    assert_eq!(
        described
            .stacks()
            .first()
            .unwrap()
            .stack_status()
            .unwrap()
            .as_str(),
        "CREATE_COMPLETE"
    );

    let policy = ecr
        .get_lifecycle_policy()
        .repository_name("ecr-cfn-lifecycle-repo")
        .send()
        .await
        .expect("get_lifecycle_policy");
    assert!(policy
        .lifecycle_policy_text()
        .map(|s| s.contains("imageCountMoreThan"))
        .unwrap_or(false));
    assert!(
        policy.last_evaluated_at().is_some(),
        "PutLifecyclePolicy data path stamps lastEvaluatedAt — provisioner must too"
    );

    cfn.delete_stack()
        .stack_name("ecr-lifecycle-stack")
        .send()
        .await
        .expect("delete_stack");

    // Repository is still gone after stack delete (cascades take down
    // the lifecycle policy with it).
    let after = ecr
        .describe_repositories()
        .repository_names("ecr-cfn-lifecycle-repo")
        .send()
        .await;
    assert!(after.is_err());
}

const SCANNING_TEMPLATE: &str = r#"{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "Scanning": {
      "Type": "AWS::ECR::RegistryScanningConfiguration",
      "Properties": {
        "ScanType": "ENHANCED",
        "Rules": [{
          "ScanFrequency": "CONTINUOUS_SCAN",
          "RepositoryFilters": [{"Filter": "prod-*", "FilterType": "WILDCARD"}]
        }]
      }
    }
  }
}"#;

#[tokio::test]
async fn cfn_provisions_ecr_registry_scanning_configuration() {
    let server = TestServer::start().await;
    let cfn = server.cloudformation_client().await;
    let ecr = server.ecr_client().await;

    cfn.create_stack()
        .stack_name("ecr-scan-stack")
        .template_body(SCANNING_TEMPLATE)
        .send()
        .await
        .expect("create_stack");

    let described = cfn
        .describe_stacks()
        .stack_name("ecr-scan-stack")
        .send()
        .await
        .expect("describe_stacks");
    assert_eq!(
        described
            .stacks()
            .first()
            .unwrap()
            .stack_status()
            .unwrap()
            .as_str(),
        "CREATE_COMPLETE"
    );

    let cfg = ecr
        .get_registry_scanning_configuration()
        .send()
        .await
        .expect("get_registry_scanning_configuration");
    let scan_cfg = cfg
        .scanning_configuration()
        .expect("scanning configuration present");
    assert_eq!(
        scan_cfg.scan_type().map(|s| s.as_str()),
        Some("ENHANCED"),
        "ScanType should match what CFN provisioned"
    );
    assert_eq!(scan_cfg.rules().len(), 1);

    cfn.delete_stack()
        .stack_name("ecr-scan-stack")
        .send()
        .await
        .expect("delete_stack");

    let after = ecr
        .get_registry_scanning_configuration()
        .send()
        .await
        .expect("get_registry_scanning_configuration");
    let after_cfg = after
        .scanning_configuration()
        .expect("config present after delete");
    assert_eq!(
        after_cfg.scan_type().map(|s| s.as_str()),
        Some("BASIC"),
        "delete should revert the registry to the AWS default scan type"
    );
    assert!(after_cfg.rules().is_empty());
}
