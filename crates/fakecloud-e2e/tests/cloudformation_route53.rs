//! CloudFormation provisioner for AWS::Route53::HostedZone, RecordSet, and HealthCheck.

mod helpers;

use aws_sdk_cloudformation::types::{Capability, OnFailure};
use helpers::TestServer;

const TEMPLATE: &str = r#"{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "Zone": {
      "Type": "AWS::Route53::HostedZone",
      "Properties": {
        "Name": "example.com.",
        "HostedZoneConfig": {"Comment": "managed by cfn"}
      }
    },
    "ApiRecord": {
      "Type": "AWS::Route53::RecordSet",
      "Properties": {
        "HostedZoneId": {"Ref": "Zone"},
        "Name": "api.example.com.",
        "Type": "A",
        "TTL": "300",
        "ResourceRecords": ["10.0.0.1", "10.0.0.2"]
      }
    },
    "HealthCheck": {
      "Type": "AWS::Route53::HealthCheck",
      "Properties": {
        "HealthCheckConfig": {
          "Type": "HTTP",
          "FullyQualifiedDomainName": "api.example.com",
          "Port": 80,
          "ResourcePath": "/health",
          "RequestInterval": 30,
          "FailureThreshold": 3
        }
      }
    }
  },
  "Outputs": {
    "ZoneId": {"Value": {"Ref": "Zone"}},
    "RecordPhysicalId": {"Value": {"Ref": "ApiRecord"}},
    "HealthCheckId": {"Value": {"Ref": "HealthCheck"}}
  }
}"#;

#[tokio::test]
async fn cfn_provisions_route53_resources() {
    let server = TestServer::start().await;
    let cfn = server.cloudformation_client().await;
    let r53 = aws_sdk_route53::Client::new(&server.aws_config().await);

    cfn.create_stack()
        .stack_name("r53-stack")
        .template_body(TEMPLATE)
        .capabilities(Capability::CapabilityIam)
        .on_failure(OnFailure::Rollback)
        .send()
        .await
        .expect("create_stack");

    let described = cfn
        .describe_stacks()
        .stack_name("r53-stack")
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

    let zone_id = outputs.get("ZoneId").expect("ZoneId output");
    let record_pid = outputs.get("RecordPhysicalId").expect("RecordPhysicalId");
    let health_id = outputs.get("HealthCheckId").expect("HealthCheckId");

    assert!(zone_id.starts_with('Z'), "zone id format: {zone_id}");
    assert!(
        record_pid.contains("api.example.com.") && record_pid.contains("|A"),
        "record physical id format: {record_pid}"
    );
    assert!(!health_id.is_empty());

    // Verify hosted zone via SDK.
    let zone = r53
        .get_hosted_zone()
        .id(*zone_id)
        .send()
        .await
        .expect("get_hosted_zone");
    let hz = zone.hosted_zone().expect("hosted zone");
    assert_eq!(hz.name(), "example.com.");

    // Verify record set landed in the zone.
    let records = r53
        .list_resource_record_sets()
        .hosted_zone_id(*zone_id)
        .send()
        .await
        .expect("list_resource_record_sets");
    let api_record = records
        .resource_record_sets()
        .iter()
        .find(|r| r.name() == "api.example.com." && r.r#type().as_str() == "A")
        .expect("api A record");
    assert_eq!(api_record.ttl(), Some(300));
    let values: Vec<&str> = api_record
        .resource_records()
        .iter()
        .map(|rr| rr.value())
        .collect();
    assert!(values.contains(&"10.0.0.1"));
    assert!(values.contains(&"10.0.0.2"));

    // Verify health check.
    let hc = r53
        .get_health_check()
        .health_check_id(*health_id)
        .send()
        .await
        .expect("get_health_check");
    let cfg = hc
        .health_check()
        .and_then(|h| h.health_check_config())
        .expect("health check config");
    assert_eq!(cfg.r#type().as_str(), "HTTP");
    assert_eq!(cfg.fully_qualified_domain_name(), Some("api.example.com"));
    assert_eq!(cfg.port(), Some(80));

    // Tear down.
    cfn.delete_stack()
        .stack_name("r53-stack")
        .send()
        .await
        .expect("delete_stack");

    let zone_after = r53.get_hosted_zone().id(*zone_id).send().await;
    assert!(zone_after.is_err(), "hosted zone should be gone");

    let hc_after = r53
        .get_health_check()
        .health_check_id(*health_id)
        .send()
        .await;
    assert!(hc_after.is_err(), "health check should be gone");
}
