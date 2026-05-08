mod helpers;

use fakecloud_conformance_macros::test_action;
use helpers::TestServer;

#[test_action("bedrock-agent", "CreateAgent", checksum = "5ff584ee")]
#[test_action("bedrock-agent", "GetAgent", checksum = "6280c0c7")]
#[test_action("bedrock-agent", "UpdateAgent", checksum = "c411f388")]
#[test_action("bedrock-agent", "DeleteAgent", checksum = "bba3c62c")]
#[test_action("bedrock-agent", "ListAgents", checksum = "66199c4d")]
#[tokio::test]
async fn bedrock_agent_crud() {
    let server = TestServer::start().await;
    let client = server.bedrock_agent_client().await;

    let create_resp = client
        .create_agent()
        .agent_name("test-agent")
        .description("Test agent")
        .send()
        .await
        .unwrap();
    let agent_id = create_resp.agent().unwrap().agent_id();

    let get_resp = client.get_agent().agent_id(agent_id).send().await.unwrap();
    assert_eq!(get_resp.agent().unwrap().agent_name(), "test-agent");

    let update_resp = client
        .update_agent()
        .agent_id(agent_id)
        .agent_name("updated-agent")
        .send()
        .await
        .unwrap();
    assert_eq!(update_resp.agent().unwrap().agent_name(), "updated-agent");

    let list_resp = client.list_agents().send().await.unwrap();
    assert_eq!(list_resp.agent_summaries().len(), 1);

    client
        .delete_agent()
        .agent_id(agent_id)
        .send()
        .await
        .unwrap();
}

#[test_action("bedrock-agent", "CreateAgentAlias", checksum = "8f06def6")]
#[test_action("bedrock-agent", "GetAgentAlias", checksum = "3186a0b3")]
#[test_action("bedrock-agent", "ListAgentAliases", checksum = "7fdc5230")]
#[test_action("bedrock-agent", "DeleteAgentAlias", checksum = "009afe01")]
#[tokio::test]
async fn bedrock_agent_alias_crud() {
    let server = TestServer::start().await;
    let client = server.bedrock_agent_client().await;

    let agent_resp = client
        .create_agent()
        .agent_name("alias-test-agent")
        .send()
        .await
        .unwrap();
    let agent_id = agent_resp.agent().unwrap().agent_id();

    let alias_resp = client
        .create_agent_alias()
        .agent_id(agent_id)
        .agent_alias_name("test-alias")
        .send()
        .await
        .unwrap();
    let alias_id = alias_resp.agent_alias().unwrap().agent_alias_id();

    let get_resp = client
        .get_agent_alias()
        .agent_id(agent_id)
        .agent_alias_id(alias_id)
        .send()
        .await
        .unwrap();
    assert_eq!(
        get_resp.agent_alias().unwrap().agent_alias_name(),
        "test-alias"
    );

    let list_resp = client
        .list_agent_aliases()
        .agent_id(agent_id)
        .send()
        .await
        .unwrap();
    assert_eq!(list_resp.agent_alias_summaries().len(), 1);

    client
        .delete_agent_alias()
        .agent_id(agent_id)
        .agent_alias_id(alias_id)
        .send()
        .await
        .unwrap();
}

#[test_action("bedrock-agent", "CreateKnowledgeBase", checksum = "793d8015")]
#[test_action("bedrock-agent", "GetKnowledgeBase", checksum = "a666dbb8")]
#[test_action("bedrock-agent", "DeleteKnowledgeBase", checksum = "fe88f584")]
#[tokio::test]
async fn bedrock_agent_knowledge_base_crud() {
    let server = TestServer::start().await;
    let client = server.bedrock_agent_client().await;

    let create_resp = client
        .create_knowledge_base()
        .name("test-kb")
        .send()
        .await
        .unwrap();
    let kb_id = create_resp.knowledge_base().unwrap().knowledge_base_id();

    let get_resp = client
        .get_knowledge_base()
        .knowledge_base_id(kb_id)
        .send()
        .await
        .unwrap();
    assert_eq!(get_resp.knowledge_base().unwrap().name(), "test-kb");

    client
        .delete_knowledge_base()
        .knowledge_base_id(kb_id)
        .send()
        .await
        .unwrap();
}

#[test_action("bedrock-agent", "TagResource", checksum = "713e885a")]
#[test_action("bedrock-agent", "ListTagsForResource", checksum = "0b6d013f")]
#[test_action("bedrock-agent", "UntagResource", checksum = "85917828")]
#[tokio::test]
async fn bedrock_agent_tags() {
    let server = TestServer::start().await;
    let client = server.bedrock_agent_client().await;

    let resp = client
        .create_agent()
        .agent_name("tag-test-agent")
        .send()
        .await
        .unwrap();
    let agent_id = resp.agent().unwrap().agent_id();
    let arn = format!("arn:aws:bedrock:us-east-1:000000000000:agent/{}", agent_id);

    client
        .tag_resource()
        .resource_arn(&arn)
        .tags("env", "test")
        .send()
        .await
        .unwrap();

    let list_resp = client
        .list_tags_for_resource()
        .resource_arn(&arn)
        .send()
        .await
        .unwrap();
    let tags = list_resp.tags().unwrap();
    assert_eq!(tags.get("env").unwrap(), "test");

    client
        .untag_resource()
        .resource_arn(&arn)
        .tag_keys("env")
        .send()
        .await
        .unwrap();

    let list_resp2 = client
        .list_tags_for_resource()
        .resource_arn(&arn)
        .send()
        .await
        .unwrap();
    assert!(list_resp2.tags().unwrap().get("env").is_none());
}
