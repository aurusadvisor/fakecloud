//! CloudFormation provisioner for AWS::KMS::Key + AWS::KMS::Alias.

mod helpers;

use aws_sdk_cloudformation::types::{Capability, OnFailure};
use helpers::TestServer;

const TEMPLATE: &str = r#"{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "AppKey": {
      "Type": "AWS::KMS::Key",
      "Properties": {
        "Description": "App data key",
        "EnableKeyRotation": true,
        "KeyUsage": "ENCRYPT_DECRYPT",
        "KeySpec": "SYMMETRIC_DEFAULT"
      }
    },
    "AppAlias": {
      "Type": "AWS::KMS::Alias",
      "Properties": {
        "AliasName": "alias/cfn-app-key",
        "TargetKeyId": {"Ref": "AppKey"}
      }
    }
  },
  "Outputs": {
    "KeyId": {"Value": {"Ref": "AppKey"}},
    "KeyArn": {"Value": {"Fn::GetAtt": ["AppKey", "Arn"]}},
    "AliasName": {"Value": {"Ref": "AppAlias"}}
  }
}"#;

#[tokio::test]
async fn cfn_provisions_and_deletes_kms_key_and_alias() {
    let server = TestServer::start().await;
    let cfn = server.cloudformation_client().await;
    let kms = server.kms_client().await;

    cfn.create_stack()
        .stack_name("kms-stack")
        .template_body(TEMPLATE)
        .capabilities(Capability::CapabilityIam)
        .on_failure(OnFailure::Rollback)
        .send()
        .await
        .expect("create_stack");

    let described = cfn
        .describe_stacks()
        .stack_name("kms-stack")
        .send()
        .await
        .expect("describe_stacks");
    let stack = described.stacks().first().expect("stack present");
    assert_eq!(stack.stack_status().unwrap().as_str(), "CREATE_COMPLETE");

    let mut key_id = None;
    let mut key_arn = None;
    let mut alias_name = None;
    for o in stack.outputs() {
        match o.output_key() {
            Some("KeyId") => key_id = o.output_value().map(|s| s.to_string()),
            Some("KeyArn") => key_arn = o.output_value().map(|s| s.to_string()),
            Some("AliasName") => alias_name = o.output_value().map(|s| s.to_string()),
            _ => {}
        }
    }
    let key_id = key_id.expect("KeyId output");
    let key_arn = key_arn.expect("KeyArn output");
    let alias_name = alias_name.expect("AliasName output");
    assert!(
        key_arn.starts_with("arn:aws:kms:") && key_arn.ends_with(&format!("key/{key_id}")),
        "unexpected arn {key_arn}"
    );
    assert_eq!(alias_name, "alias/cfn-app-key");

    let described_key = kms
        .describe_key()
        .key_id(&key_id)
        .send()
        .await
        .expect("describe_key");
    let metadata = described_key.key_metadata().expect("key metadata");
    assert_eq!(metadata.key_id(), key_id);
    assert_eq!(metadata.description(), Some("App data key"));
    assert_eq!(
        metadata.key_usage().map(|u| u.as_str()),
        Some("ENCRYPT_DECRYPT")
    );

    let listed = kms.list_aliases().send().await.expect("list_aliases");
    let alias = listed
        .aliases()
        .iter()
        .find(|a| a.alias_name() == Some(&alias_name))
        .expect("alias present");
    assert_eq!(alias.target_key_id(), Some(key_id.as_str()));

    cfn.delete_stack()
        .stack_name("kms-stack")
        .send()
        .await
        .expect("delete_stack");

    let after = kms.describe_key().key_id(&key_id).send().await;
    assert!(after.is_err(), "key should be gone after stack deletion");
    let listed_after = kms.list_aliases().send().await.expect("list_aliases after");
    assert!(
        !listed_after
            .aliases()
            .iter()
            .any(|a| a.alias_name() == Some(&alias_name)),
        "alias should be gone after stack deletion"
    );
}

const REPLICA_TEMPLATE: &str = r#"{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "Primary": {
      "Type": "AWS::KMS::Key",
      "Properties": {
        "Description": "primary mrk",
        "MultiRegion": true,
        "KeyPolicy": {
          "Version": "2012-10-17",
          "Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "kms:*", "Resource": "*"}]
        }
      }
    },
    "Replica": {
      "Type": "AWS::KMS::ReplicaKey",
      "Properties": {
        "Description": "replica mrk",
        "PrimaryKeyArn": {"Fn::GetAtt": ["Primary", "Arn"]},
        "Enabled": true
      }
    }
  },
  "Outputs": {
    "PrimaryArn": {"Value": {"Fn::GetAtt": ["Primary", "Arn"]}},
    "PrimaryKeyId": {"Value": {"Ref": "Primary"}},
    "ReplicaArn": {"Value": {"Fn::GetAtt": ["Replica", "Arn"]}},
    "ReplicaKeyId": {"Value": {"Fn::GetAtt": ["Replica", "KeyId"]}}
  }
}"#;

#[tokio::test]
async fn cfn_provisions_kms_replica_key() {
    let server = TestServer::start().await;
    let cfn = server.cloudformation_client().await;
    let kms = aws_sdk_kms::Client::new(&server.aws_config().await);

    cfn.create_stack()
        .stack_name("kms-replica-stack")
        .template_body(REPLICA_TEMPLATE)
        .send()
        .await
        .expect("create_stack");

    let described = cfn
        .describe_stacks()
        .stack_name("kms-replica-stack")
        .send()
        .await
        .expect("describe_stacks");
    let stack = described.stacks().first().unwrap();
    assert_eq!(stack.stack_status().unwrap().as_str(), "CREATE_COMPLETE");
    let outputs: std::collections::HashMap<&str, &str> = stack
        .outputs()
        .iter()
        .filter_map(|o| Some((o.output_key()?, o.output_value()?)))
        .collect();
    let primary_key_id = outputs
        .get("PrimaryKeyId")
        .expect("PrimaryKeyId")
        .to_string();
    let replica_key_id = outputs
        .get("ReplicaKeyId")
        .expect("ReplicaKeyId")
        .to_string();
    let replica_arn = outputs.get("ReplicaArn").expect("ReplicaArn").to_string();

    // Both primary and replica are multi-region keys (fakecloud uses a
    // synthesized replica key_id since it runs in a single region).
    assert!(primary_key_id.starts_with("mrk-"));
    assert!(replica_key_id.starts_with("mrk-replica-"));
    assert!(replica_arn.contains(&replica_key_id));

    // DescribeKey on the replica ARN should report MultiRegion=true.
    let described = kms
        .describe_key()
        .key_id(&replica_arn)
        .send()
        .await
        .expect("describe_key replica");
    let metadata = described.key_metadata().expect("metadata");
    assert_eq!(metadata.multi_region(), Some(true));
    let mrc = metadata
        .multi_region_configuration()
        .expect("multi-region config");
    assert_eq!(
        mrc.multi_region_key_type().map(|t| t.as_str()),
        Some("REPLICA"),
    );

    cfn.delete_stack()
        .stack_name("kms-replica-stack")
        .send()
        .await
        .expect("delete_stack");

    let replica_after = kms.describe_key().key_id(&replica_arn).send().await;
    assert!(
        replica_after.is_err(),
        "replica should be gone after stack deletion"
    );
}

const ASYM_TEMPLATE: &str = r#"{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "SigningKey": {
      "Type": "AWS::KMS::Key",
      "Properties": {
        "Description": "RSA signing key",
        "KeyUsage": "SIGN_VERIFY",
        "KeySpec": "RSA_2048"
      }
    },
    "AgreementKey": {
      "Type": "AWS::KMS::Key",
      "Properties": {
        "Description": "ECC key agreement",
        "KeyUsage": "KEY_AGREEMENT",
        "KeySpec": "ECC_NIST_P256"
      }
    },
    "MacKey": {
      "Type": "AWS::KMS::Key",
      "Properties": {
        "Description": "HMAC mac key",
        "KeyUsage": "GENERATE_VERIFY_MAC",
        "KeySpec": "HMAC_256"
      }
    }
  },
  "Outputs": {
    "SigningKeyId": {"Value": {"Ref": "SigningKey"}},
    "AgreementKeyId": {"Value": {"Ref": "AgreementKey"}},
    "MacKeyId": {"Value": {"Ref": "MacKey"}}
  }
}"#;

/// CFN must accept SIGN_VERIFY (asymmetric RSA), KEY_AGREEMENT (ECC),
/// and GENERATE_VERIFY_MAC (HMAC) usages, not just symmetric keys.
/// The pre-BB14 provisioner rejected anything that wasn't
/// SYMMETRIC_DEFAULT or HMAC, which left a parity gap with real
/// CloudFormation.
#[tokio::test]
async fn cfn_provisions_asymmetric_and_mac_keys() {
    let server = TestServer::start().await;
    let cfn = server.cloudformation_client().await;
    let kms = server.kms_client().await;

    cfn.create_stack()
        .stack_name("asym-kms-stack")
        .template_body(ASYM_TEMPLATE)
        .send()
        .await
        .expect("create_stack");

    let described = cfn
        .describe_stacks()
        .stack_name("asym-kms-stack")
        .send()
        .await
        .expect("describe_stacks");
    let stack = described.stacks().first().expect("stack present");
    assert_eq!(stack.stack_status().unwrap().as_str(), "CREATE_COMPLETE");

    let outputs: std::collections::HashMap<&str, &str> = stack
        .outputs()
        .iter()
        .filter_map(|o| Some((o.output_key()?, o.output_value()?)))
        .collect();

    let signing = kms
        .describe_key()
        .key_id(*outputs.get("SigningKeyId").unwrap())
        .send()
        .await
        .expect("describe signing key");
    let signing_meta = signing.key_metadata().unwrap();
    assert_eq!(signing_meta.key_usage().unwrap().as_str(), "SIGN_VERIFY");
    assert_eq!(signing_meta.key_spec().unwrap().as_str(), "RSA_2048");
    assert!(
        !signing_meta.signing_algorithms().is_empty(),
        "signing algorithms should be populated for an RSA key",
    );

    // GetPublicKey must work — that's the smoke test for asymmetric
    // keypair generation having actually run during CFN provisioning.
    let pub_key = kms
        .get_public_key()
        .key_id(*outputs.get("SigningKeyId").unwrap())
        .send()
        .await
        .expect("get_public_key");
    assert!(pub_key.public_key().is_some());

    let agreement = kms
        .describe_key()
        .key_id(*outputs.get("AgreementKeyId").unwrap())
        .send()
        .await
        .expect("describe agreement key");
    assert_eq!(
        agreement
            .key_metadata()
            .unwrap()
            .key_usage()
            .unwrap()
            .as_str(),
        "KEY_AGREEMENT"
    );

    let mac = kms
        .describe_key()
        .key_id(*outputs.get("MacKeyId").unwrap())
        .send()
        .await
        .expect("describe mac key");
    assert!(
        !mac.key_metadata().unwrap().mac_algorithms().is_empty(),
        "MAC key should publish supported HMAC algorithms",
    );
}

const UPDATE_TEMPLATE_V1: &str = r#"{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "AppKey": {
      "Type": "AWS::KMS::Key",
      "Properties": {
        "Description": "v1 description",
        "EnableKeyRotation": false,
        "Enabled": true
      }
    },
    "OtherKey": {
      "Type": "AWS::KMS::Key",
      "Properties": {
        "Description": "alias re-target",
        "Enabled": true
      }
    },
    "AppAlias": {
      "Type": "AWS::KMS::Alias",
      "Properties": {
        "AliasName": "alias/cfn-update-test",
        "TargetKeyId": {"Ref": "AppKey"}
      }
    }
  },
  "Outputs": {
    "KeyId": {"Value": {"Ref": "AppKey"}},
    "OtherKeyId": {"Value": {"Ref": "OtherKey"}}
  }
}"#;

const UPDATE_TEMPLATE_V2: &str = r#"{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "AppKey": {
      "Type": "AWS::KMS::Key",
      "Properties": {
        "Description": "v2 description",
        "EnableKeyRotation": true,
        "Enabled": false
      }
    },
    "OtherKey": {
      "Type": "AWS::KMS::Key",
      "Properties": {
        "Description": "alias re-target",
        "Enabled": true
      }
    },
    "AppAlias": {
      "Type": "AWS::KMS::Alias",
      "Properties": {
        "AliasName": "alias/cfn-update-test",
        "TargetKeyId": {"Ref": "OtherKey"}
      }
    }
  },
  "Outputs": {
    "KeyId": {"Value": {"Ref": "AppKey"}},
    "OtherKeyId": {"Value": {"Ref": "OtherKey"}}
  }
}"#;

/// Update flow: changing description / enabled / EnableKeyRotation on
/// an `AWS::KMS::Key` should land in place via `update_resource`, and
/// repointing an `AWS::KMS::Alias` at a different key shouldn't drop
/// the alias.
#[tokio::test]
async fn cfn_updates_kms_key_and_repoints_alias() {
    let server = TestServer::start().await;
    let cfn = server.cloudformation_client().await;
    let kms = server.kms_client().await;

    cfn.create_stack()
        .stack_name("kms-update-stack")
        .template_body(UPDATE_TEMPLATE_V1)
        .send()
        .await
        .expect("create_stack");

    let stack_v1 = cfn
        .describe_stacks()
        .stack_name("kms-update-stack")
        .send()
        .await
        .expect("describe v1");
    let v1_outputs: std::collections::HashMap<&str, &str> = stack_v1
        .stacks()
        .first()
        .unwrap()
        .outputs()
        .iter()
        .filter_map(|o| Some((o.output_key()?, o.output_value()?)))
        .collect();
    let original_key_id = v1_outputs.get("KeyId").unwrap().to_string();

    cfn.update_stack()
        .stack_name("kms-update-stack")
        .template_body(UPDATE_TEMPLATE_V2)
        .send()
        .await
        .expect("update_stack");

    let stack_v2 = cfn
        .describe_stacks()
        .stack_name("kms-update-stack")
        .send()
        .await
        .expect("describe v2");
    let outputs: std::collections::HashMap<&str, &str> = stack_v2
        .stacks()
        .first()
        .unwrap()
        .outputs()
        .iter()
        .filter_map(|o| Some((o.output_key()?, o.output_value()?)))
        .collect();
    let after_key_id = outputs.get("KeyId").unwrap().to_string();
    let other_key_id = outputs.get("OtherKeyId").unwrap().to_string();

    // Same physical key — update was in place, not a replacement.
    assert_eq!(after_key_id, original_key_id);

    let described = kms
        .describe_key()
        .key_id(&after_key_id)
        .send()
        .await
        .expect("describe after update");
    let metadata = described.key_metadata().unwrap();
    assert_eq!(metadata.description(), Some("v2 description"));
    assert!(!metadata.enabled());

    let rotation = kms
        .get_key_rotation_status()
        .key_id(&after_key_id)
        .send()
        .await
        .expect("rotation status");
    assert!(rotation.key_rotation_enabled());

    // Alias should now point at OtherKey.
    let aliases = kms.list_aliases().send().await.expect("list_aliases");
    let alias = aliases
        .aliases()
        .iter()
        .find(|a| a.alias_name() == Some("alias/cfn-update-test"))
        .expect("alias still present");
    assert_eq!(alias.target_key_id(), Some(other_key_id.as_str()));
}
