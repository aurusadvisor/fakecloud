package fakecloud

import (
	"context"
	"fmt"
	"net/url"
)

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

// GetTasks lists every task fakecloud has seen. Pass empty strings to
// skip the cluster / status filters.
func (c *ECSClient) GetTasks(ctx context.Context, cluster, status string) (*EcsTasksResponse, error) {
	path := "/_fakecloud/ecs/tasks"
	q := url.Values{}
	if cluster != "" {
		q.Set("cluster", cluster)
	}
	if status != "" {
		q.Set("status", status)
	}
	if enc := q.Encode(); enc != "" {
		path += "?" + enc
	}
	var out EcsTasksResponse
	if err := c.fc.doGet(ctx, path, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetTaskLogs returns the captured docker stdout/stderr for a task.
func (c *ECSClient) GetTaskLogs(ctx context.Context, taskID string) (*EcsTaskLogsResponse, error) {
	var out EcsTaskLogsResponse
	if err := c.fc.doGet(ctx, fmt.Sprintf("/_fakecloud/ecs/tasks/%s/logs", taskID), &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ForceStopTask sends SIGTERM (then SIGKILL after 10s) to the task's
// running container via the runtime.
func (c *ECSClient) ForceStopTask(ctx context.Context, taskID string) (*EcsTask, error) {
	var out EcsTask
	if err := c.fc.doPost(ctx, fmt.Sprintf("/_fakecloud/ecs/tasks/%s/force-stop", taskID), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// MarkTaskFailed flips a task to STOPPED without killing the container —
// useful for simulating failed tasks deterministically in tests.
func (c *ECSClient) MarkTaskFailed(ctx context.Context, taskID string, req *EcsMarkFailedRequest) (*EcsTask, error) {
	var out EcsTask
	if err := c.fc.doPost(ctx, fmt.Sprintf("/_fakecloud/ecs/tasks/%s/mark-failed", taskID), req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetEvents replays the lifecycle event log.
func (c *ECSClient) GetEvents(ctx context.Context) (*EcsEventsResponse, error) {
	var out EcsEventsResponse
	if err := c.fc.doGet(ctx, "/_fakecloud/ecs/events", &out); err != nil {
		return nil, err
	}
	return &out, nil
}
