//! CloudFormation provisioner for AWS::CloudFront::* metadata resources.

mod helpers;

use aws_sdk_cloudformation::types::{Capability, OnFailure};
use helpers::TestServer;

const TEMPLATE: &str = r#"{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "OAI": {
      "Type": "AWS::CloudFront::CloudFrontOriginAccessIdentity",
      "Properties": {
        "CloudFrontOriginAccessIdentityConfig": {"Comment": "managed by cfn"}
      }
    },
    "OAC": {
      "Type": "AWS::CloudFront::OriginAccessControl",
      "Properties": {
        "OriginAccessControlConfig": {
          "Name": "cfn-oac",
          "OriginAccessControlOriginType": "s3",
          "SigningBehavior": "always",
          "SigningProtocol": "sigv4"
        }
      }
    },
    "PubKey": {
      "Type": "AWS::CloudFront::PublicKey",
      "Properties": {
        "PublicKeyConfig": {
          "CallerReference": "cfn-pk-1",
          "Name": "cfn-pubkey",
          "EncodedKey": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\n-----END PUBLIC KEY-----"
        }
      }
    },
    "CachePolicy": {
      "Type": "AWS::CloudFront::CachePolicy",
      "Properties": {
        "CachePolicyConfig": {
          "Name": "cfn-cache",
          "MinTTL": 1,
          "DefaultTTL": 60,
          "MaxTTL": 3600
        }
      }
    },
    "OriginReqPolicy": {
      "Type": "AWS::CloudFront::OriginRequestPolicy",
      "Properties": {
        "OriginRequestPolicyConfig": {
          "Name": "cfn-origin-req",
          "HeadersConfig": {"HeaderBehavior": "none"},
          "CookiesConfig": {"CookieBehavior": "none"},
          "QueryStringsConfig": {"QueryStringBehavior": "none"}
        }
      }
    },
    "RespHdrPolicy": {
      "Type": "AWS::CloudFront::ResponseHeadersPolicy",
      "Properties": {
        "ResponseHeadersPolicyConfig": {
          "Name": "cfn-resp-hdr",
          "Comment": "managed by cfn"
        }
      }
    }
  },
  "Outputs": {
    "OAIId": {"Value": {"Ref": "OAI"}},
    "OACId": {"Value": {"Ref": "OAC"}},
    "PubKeyId": {"Value": {"Ref": "PubKey"}},
    "CachePolicyId": {"Value": {"Ref": "CachePolicy"}},
    "OriginReqPolicyId": {"Value": {"Ref": "OriginReqPolicy"}},
    "RespHdrPolicyId": {"Value": {"Ref": "RespHdrPolicy"}}
  }
}"#;

#[tokio::test]
async fn cfn_provisions_cloudfront_resources() {
    let server = TestServer::start().await;
    let cfn = server.cloudformation_client().await;
    let cf = aws_sdk_cloudfront::Client::new(&server.aws_config().await);

    cfn.create_stack()
        .stack_name("cf-stack")
        .template_body(TEMPLATE)
        .capabilities(Capability::CapabilityIam)
        .on_failure(OnFailure::Rollback)
        .send()
        .await
        .expect("create_stack");

    let described = cfn
        .describe_stacks()
        .stack_name("cf-stack")
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

    let oai_id = outputs.get("OAIId").expect("OAIId");
    let oac_id = outputs.get("OACId").expect("OACId");
    let pk_id = outputs.get("PubKeyId").expect("PubKeyId");
    let cache_id = outputs.get("CachePolicyId").expect("CachePolicyId");
    let orp_id = outputs.get("OriginReqPolicyId").expect("OriginReqPolicyId");
    let rhp_id = outputs.get("RespHdrPolicyId").expect("RespHdrPolicyId");

    assert!(oai_id.starts_with('E'), "OAI id: {oai_id}");
    assert!(oac_id.starts_with('E'), "OAC id: {oac_id}");
    assert!(pk_id.starts_with('K'), "PublicKey id: {pk_id}");
    assert!(cache_id.starts_with("CP"), "CachePolicy id: {cache_id}");
    assert!(orp_id.starts_with("ORP"), "OriginReqPolicy id: {orp_id}");
    assert!(rhp_id.starts_with("RHP"), "RespHdrPolicy id: {rhp_id}");

    // Verify a couple via SDK to prove the records are actually retrievable.
    let oai_get = cf
        .get_cloud_front_origin_access_identity()
        .id(*oai_id)
        .send()
        .await
        .expect("get_cloud_front_origin_access_identity");
    assert!(oai_get.cloud_front_origin_access_identity().is_some());

    let oac_get = cf
        .get_origin_access_control()
        .id(*oac_id)
        .send()
        .await
        .expect("get_origin_access_control");
    let oac_cfg = oac_get
        .origin_access_control()
        .and_then(|o| o.origin_access_control_config())
        .expect("origin access control config");
    assert_eq!(oac_cfg.name(), "cfn-oac");

    let cache_get = cf
        .get_cache_policy()
        .id(*cache_id)
        .send()
        .await
        .expect("get_cache_policy");
    let cache_cfg = cache_get
        .cache_policy()
        .and_then(|p| p.cache_policy_config())
        .expect("cache policy config");
    assert_eq!(cache_cfg.name(), "cfn-cache");
    assert_eq!(cache_cfg.min_ttl(), 1);

    cfn.delete_stack()
        .stack_name("cf-stack")
        .send()
        .await
        .expect("delete_stack");

    let oai_after = cf
        .get_cloud_front_origin_access_identity()
        .id(*oai_id)
        .send()
        .await;
    assert!(oai_after.is_err(), "OAI should be gone");
}
