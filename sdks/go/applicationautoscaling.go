package fakecloud

import "context"

// ApplicationAutoScalingClient provides access to the Application
// Auto Scaling watcher introspection endpoint.
type ApplicationAutoScalingClient struct {
	fc *FakeCloud
}

// Tick forces the watcher to evaluate every scaling policy now.
// Returns the number of policies that applied a capacity change on
// this tick. Useful in tests so callers don't have to wait for the
// wall-clock 15s interval.
func (c *ApplicationAutoScalingClient) Tick(ctx context.Context) (*AppAsTickResponse, error) {
	var out AppAsTickResponse
	if err := c.fc.doPost(ctx, "/_fakecloud/application-autoscaling/tick", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ScheduledTick forces the scheduled-action executor to evaluate every
// ScheduledAction now. Returns the number of actions that fired on
// this tick. Useful in tests so callers don't have to wait for the
// wall-clock 30s interval.
func (c *ApplicationAutoScalingClient) ScheduledTick(ctx context.Context) (*AppAsScheduledTickResponse, error) {
	var out AppAsScheduledTickResponse
	if err := c.fc.doPost(ctx, "/_fakecloud/application-autoscaling/scheduled-tick", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
