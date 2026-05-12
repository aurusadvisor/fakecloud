package fakecloud

import "context"

// AthenaClient provides access to Athena introspection endpoints.
type AthenaClient struct {
	fc *FakeCloud
}

// GetNamedQueries lists every named query stored in the Athena registry
// across all workgroups for the default account. The response includes a
// LastUsedAt timestamp that the server bumps each time StartQueryExecution
// resolves the query string by NamedQueryId.
func (c *AthenaClient) GetNamedQueries(ctx context.Context) (*AthenaNamedQueriesResponse, error) {
	var out AthenaNamedQueriesResponse
	if err := c.fc.doGet(ctx, "/_fakecloud/athena/named-queries", &out); err != nil {
		return nil, err
	}
	return &out, nil
}
