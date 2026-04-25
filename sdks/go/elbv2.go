package fakecloud

import "context"

// ELBv2Client provides access to ELBv2 introspection endpoints —
// the persisted control-plane state of every Application/Network/Gateway
// load balancer fakecloud has seen, plus their target groups, listeners,
// and rules.
type ELBv2Client struct {
	fc *FakeCloud
}

// GetLoadBalancers lists every load balancer across every account.
func (c *ELBv2Client) GetLoadBalancers(ctx context.Context) (*Elbv2LoadBalancersResponse, error) {
	var out Elbv2LoadBalancersResponse
	if err := c.fc.doGet(ctx, "/_fakecloud/elbv2/load-balancers", &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetTargetGroups lists every target group across every account.
func (c *ELBv2Client) GetTargetGroups(ctx context.Context) (*Elbv2TargetGroupsResponse, error) {
	var out Elbv2TargetGroupsResponse
	if err := c.fc.doGet(ctx, "/_fakecloud/elbv2/target-groups", &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetListeners lists every listener across every account.
func (c *ELBv2Client) GetListeners(ctx context.Context) (*Elbv2ListenersResponse, error) {
	var out Elbv2ListenersResponse
	if err := c.fc.doGet(ctx, "/_fakecloud/elbv2/listeners", &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetRules lists every listener rule across every account, including
// the default rules that AWS auto-creates for each listener.
func (c *ELBv2Client) GetRules(ctx context.Context) (*Elbv2RulesResponse, error) {
	var out Elbv2RulesResponse
	if err := c.fc.doGet(ctx, "/_fakecloud/elbv2/rules", &out); err != nil {
		return nil, err
	}
	return &out, nil
}
