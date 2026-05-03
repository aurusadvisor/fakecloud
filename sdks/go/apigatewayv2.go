package fakecloud

import (
	"context"
)

// ApiGatewayV2Client provides access to API Gateway v2 introspection endpoints.
type ApiGatewayV2Client struct {
	fc *FakeCloud
}

// GetRequests lists all HTTP API requests that were received and processed.
func (c *ApiGatewayV2Client) GetRequests(ctx context.Context) (*ApiGatewayV2RequestsResponse, error) {
	var out ApiGatewayV2RequestsResponse
	if err := c.fc.doGet(ctx, "/_fakecloud/apigatewayv2/requests", &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetConnections lists every live WebSocket connection currently registered
// with the fakecloud API Gateway v2 data plane.
func (c *ApiGatewayV2Client) GetConnections(ctx context.Context) (*ApiGatewayV2ConnectionsResponse, error) {
	var out ApiGatewayV2ConnectionsResponse
	if err := c.fc.doGet(ctx, "/_fakecloud/apigatewayv2/connections", &out); err != nil {
		return nil, err
	}
	return &out, nil
}
