package fakecloud

import "context"

// ECSClient provides access to ECS introspection endpoints.
type ECSClient struct {
	fc *FakeCloud
}

// GetClusters lists every ECS cluster fakecloud has seen, across every
// account, sorted by cluster ARN.
func (c *ECSClient) GetClusters(ctx context.Context) (*EcsClustersResponse, error) {
	var out EcsClustersResponse
	if err := c.fc.doGet(ctx, "/_fakecloud/ecs/clusters", &out); err != nil {
		return nil, err
	}
	return &out, nil
}
