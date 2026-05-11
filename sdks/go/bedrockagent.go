package fakecloud

// BedrockAgentClient is the Bedrock Agent (control plane) sub-client.
//
// The fakecloud Bedrock Agent service has no admin/introspection endpoints
// today; this client exists so callers can hold a typed handle alongside the
// other Bedrock sub-clients and so future helpers can land here without an
// API break.
type BedrockAgentClient struct {
	fc *FakeCloud
}

// BedrockAgentRuntimeClient is the Bedrock Agent Runtime (data plane)
// sub-client. Placeholder for future introspection helpers around
// InvokeAgent, Retrieve, and RetrieveAndGenerate.
type BedrockAgentRuntimeClient struct {
	fc *FakeCloud
}
