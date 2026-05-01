//! CloudFormation provisioner for AWS::ECS::Cluster + TaskDefinition + Service + CapacityProvider.

mod helpers;

use aws_sdk_cloudformation::types::{Capability, OnFailure};
use helpers::TestServer;

const TEMPLATE: &str = r#"{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "Cluster": {
      "Type": "AWS::ECS::Cluster",
      "Properties": {
        "ClusterName": "cfn-ecs-cluster",
        "ClusterSettings": [{"Name": "containerInsights", "Value": "enhanced"}]
      }
    },
    "CP": {
      "Type": "AWS::ECS::CapacityProvider",
      "Properties": {
        "Name": "cfn-cp"
      }
    },
    "TaskDef": {
      "Type": "AWS::ECS::TaskDefinition",
      "Properties": {
        "Family": "cfn-task",
        "NetworkMode": "awsvpc",
        "RequiresCompatibilities": ["FARGATE"],
        "Cpu": "256",
        "Memory": "512",
        "ContainerDefinitions": [
          {
            "Name": "web",
            "Image": "nginx:alpine",
            "Essential": true,
            "PortMappings": [{"ContainerPort": 80, "Protocol": "tcp"}]
          }
        ]
      }
    },
    "Svc": {
      "Type": "AWS::ECS::Service",
      "Properties": {
        "ServiceName": "cfn-svc",
        "Cluster": {"Ref": "Cluster"},
        "TaskDefinition": {"Ref": "TaskDef"},
        "DesiredCount": 1,
        "LaunchType": "FARGATE",
        "DeploymentConfiguration": {
          "MinimumHealthyPercent": 50,
          "MaximumPercent": 200
        }
      }
    }
  },
  "Outputs": {
    "ClusterName": {"Value": {"Ref": "Cluster"}},
    "ClusterArn": {"Value": {"Fn::GetAtt": ["Cluster", "Arn"]}},
    "CpName": {"Value": {"Ref": "CP"}},
    "CpArn": {"Value": {"Fn::GetAtt": ["CP", "Arn"]}},
    "TaskDefArn": {"Value": {"Ref": "TaskDef"}},
    "ServiceArn": {"Value": {"Fn::GetAtt": ["Svc", "ServiceArn"]}}
  }
}"#;

#[tokio::test]
async fn cfn_provisions_ecs_cluster_taskdef_service_capacity_provider() {
    let server = TestServer::start().await;
    let cfn = server.cloudformation_client().await;
    let ecs = aws_sdk_ecs::Client::new(&server.aws_config().await);

    cfn.create_stack()
        .stack_name("ecs-stack")
        .template_body(TEMPLATE)
        .capabilities(Capability::CapabilityIam)
        .on_failure(OnFailure::Rollback)
        .send()
        .await
        .expect("create_stack");

    let described = cfn
        .describe_stacks()
        .stack_name("ecs-stack")
        .send()
        .await
        .expect("describe_stacks");
    let stack = described.stacks().first().expect("stack present");
    assert_eq!(stack.stack_status().unwrap().as_str(), "CREATE_COMPLETE");

    let mut outs = std::collections::HashMap::new();
    for o in stack.outputs() {
        if let (Some(k), Some(v)) = (o.output_key(), o.output_value()) {
            outs.insert(k.to_string(), v.to_string());
        }
    }
    assert_eq!(
        outs.get("ClusterName").map(|s| s.as_str()),
        Some("cfn-ecs-cluster")
    );
    assert!(outs
        .get("ClusterArn")
        .unwrap()
        .contains(":cluster/cfn-ecs-cluster"));
    assert_eq!(outs.get("CpName").map(|s| s.as_str()), Some("cfn-cp"));
    assert!(outs
        .get("CpArn")
        .unwrap()
        .contains(":capacity-provider/cfn-cp"));
    assert!(outs
        .get("TaskDefArn")
        .unwrap()
        .contains(":task-definition/cfn-task:1"));
    assert!(outs
        .get("ServiceArn")
        .unwrap()
        .contains(":service/cfn-ecs-cluster/cfn-svc"));

    // Verify cluster + service via SDK.
    let clusters = ecs
        .describe_clusters()
        .clusters("cfn-ecs-cluster")
        .send()
        .await
        .expect("describe_clusters");
    assert_eq!(
        clusters.clusters().first().and_then(|c| c.cluster_name()),
        Some("cfn-ecs-cluster")
    );

    let svcs = ecs
        .describe_services()
        .cluster("cfn-ecs-cluster")
        .services("cfn-svc")
        .send()
        .await
        .expect("describe_services");
    assert_eq!(
        svcs.services().first().and_then(|s| s.service_name()),
        Some("cfn-svc")
    );
    assert_eq!(svcs.services().first().map(|s| s.desired_count()), Some(1));

    let td = ecs
        .describe_task_definition()
        .task_definition("cfn-task:1")
        .send()
        .await
        .expect("describe_task_definition");
    assert_eq!(
        td.task_definition().and_then(|t| t.family()),
        Some("cfn-task")
    );

    cfn.delete_stack()
        .stack_name("ecs-stack")
        .send()
        .await
        .expect("delete_stack");

    // Cluster gone after stack delete.
    let after = ecs
        .describe_clusters()
        .clusters("cfn-ecs-cluster")
        .send()
        .await
        .expect("describe_clusters after delete");
    let still_active = after
        .clusters()
        .iter()
        .any(|c| c.cluster_name() == Some("cfn-ecs-cluster") && c.status() == Some("ACTIVE"));
    assert!(
        !still_active,
        "cluster should be gone or non-active after stack deletion"
    );
}
