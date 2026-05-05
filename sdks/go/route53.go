package fakecloud

import (
	"context"
	"fmt"
)

// Route53Client provides access to Route 53 admin endpoints.
//
// Wraps the per-health-check status admin endpoint that lets tests flip a
// stored health check between healthy and unhealthy without a live prober,
// so failover and multi-value routing can be exercised end-to-end.
type Route53Client struct {
	fc *FakeCloud
}

// SetHealthCheckStatusRequest is the JSON body sent to the admin endpoint.
//
// Status is one of "Success", "Failure", "Timeout", "DnsError",
// "InsufficientDataPoints", "Unknown". Reason is appended to the <Status>
// element returned by GetHealthCheckStatus for failure-flavoured statuses
// (Failure, Timeout, DnsError); ignored otherwise.
type SetHealthCheckStatusRequest struct {
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
}

// SetHealthCheckStatus flips a Route 53 health check's reported status.
// Pass an empty Reason to omit it (the prior reason is preserved).
func (c *Route53Client) SetHealthCheckStatus(
	ctx context.Context,
	healthCheckID string,
	req *SetHealthCheckStatusRequest,
) error {
	path := fmt.Sprintf("/_fakecloud/route53/health-checks/%s/status", healthCheckID)
	return c.fc.doPost(ctx, path, req, nil)
}
