package fakecloud

import "context"

// BedrockAgentClient is the Bedrock Agent (control plane) introspection
// sub-client. It exposes /_fakecloud/bedrock-agent/* read-only state for
// test assertions.
type BedrockAgentClient struct {
	fc *FakeCloud
}

// BedrockAgentRuntimeClient is the Bedrock Agent Runtime (data plane)
// introspection sub-client. It exposes /_fakecloud/bedrock-agent-runtime/*
// read-only state for test assertions.
type BedrockAgentRuntimeClient struct {
	fc *FakeCloud
}

// GetAgents returns every recorded Bedrock Agent control-plane row with
// its aliases, versions, knowledge-base attachments, and collaborators
// flattened into one shape per agent.
func (c *BedrockAgentClient) GetAgents(ctx context.Context) (*BedrockAgentAgentsResponse, error) {
	var out BedrockAgentAgentsResponse
	if err := c.fc.doGet(ctx, "/_fakecloud/bedrock-agent/agents", &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetInvocations returns every InvokeAgent / InvokeInlineAgent /
// InvokeFlow / Retrieve / RetrieveAndGenerate / CreateInvocation row the
// runtime has recorded since the last reset.
func (c *BedrockAgentRuntimeClient) GetInvocations(ctx context.Context) (*BedrockAgentRuntimeInvocationsResponse, error) {
	var out BedrockAgentRuntimeInvocationsResponse
	if err := c.fc.doGet(ctx, "/_fakecloud/bedrock-agent-runtime/invocations", &out); err != nil {
		return nil, err
	}
	return &out, nil
}
