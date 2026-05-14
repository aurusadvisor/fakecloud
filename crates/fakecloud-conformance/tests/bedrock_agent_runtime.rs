use fakecloud_testkit::TestServer;

#[tokio::test]
async fn test_retrieve() {
    let fc = TestServer::start().await;
    let client = fc.bedrock_agent_runtime_client().await;

    let resp = client
        .retrieve()
        .knowledge_base_id("testkbid01")
        .retrieval_query(
            aws_sdk_bedrockagentruntime::types::KnowledgeBaseQuery::builder()
                .text("test query")
                .build(),
        )
        .send()
        .await;

    assert!(resp.is_ok(), "Retrieve failed: {:?}", resp.err());
    let resp = resp.unwrap();
    assert!(!resp.retrieval_results.is_empty());
}

#[tokio::test]
async fn test_retrieve_and_generate() {
    let fc = TestServer::start().await;
    let client = fc.bedrock_agent_runtime_client().await;

    let resp = client
        .retrieve_and_generate()
        .input(
            aws_sdk_bedrockagentruntime::types::RetrieveAndGenerateInput::builder()
                .text("What is Bedrock?")
                .build()
                .unwrap(),
        )
        .send()
        .await;

    assert!(resp.is_ok(), "RetrieveAndGenerate failed: {:?}", resp.err());
    let resp = resp.unwrap();
    assert!(!resp.session_id.is_empty());
    assert!(resp.output.is_some());
}
