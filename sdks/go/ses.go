package fakecloud

import "context"

// SESClient provides access to SES introspection endpoints.
type SESClient struct {
	fc *FakeCloud
}

// GetEmails lists all emails sent through the SES emulator.
func (c *SESClient) GetEmails(ctx context.Context) (*SESEmailsResponse, error) {
	var out SESEmailsResponse
	if err := c.fc.doGet(ctx, "/_fakecloud/ses/emails", &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// SimulateInbound simulates an inbound email (SES receipt rules).
func (c *SESClient) SimulateInbound(ctx context.Context, req *InboundEmailRequest) (*InboundEmailResponse, error) {
	var out InboundEmailResponse
	if err := c.fc.doPost(ctx, "/_fakecloud/ses/inbound", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetMetrics returns SES emulator counters (e.g. suppressed drops).
func (c *SESClient) GetMetrics(ctx context.Context) (*SESMetrics, error) {
	var out SESMetrics
	if err := c.fc.doGet(ctx, "/_fakecloud/ses/metrics", &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// SetMailFromStatus overrides the MAIL FROM domain verification status for
// an identity. Status must be one of NotStarted/Pending/Success/Failed.
func (c *SESClient) SetMailFromStatus(ctx context.Context, identity, status string) (*SESMailFromStatusResponse, error) {
	var out SESMailFromStatusResponse
	path := "/_fakecloud/ses/identities/" + identity + "/mail-from-status"
	if err := c.fc.doPost(ctx, path, &SESMailFromStatusRequest{Status: status}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetDkimPublicKey returns the DKIM selector + public key for an identity.
func (c *SESClient) GetDkimPublicKey(ctx context.Context, identity string) (*SESDkimPublicKey, error) {
	var out SESDkimPublicKey
	path := "/_fakecloud/ses/identities/" + identity + "/dkim-public-key"
	if err := c.fc.doGet(ctx, path, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetBounces returns all bounces queued via SES SendBounce.
func (c *SESClient) GetBounces(ctx context.Context) (*SESBouncesResponse, error) {
	var out SESBouncesResponse
	if err := c.fc.doGet(ctx, "/_fakecloud/ses/bounces", &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetMessageInsights returns per-message delivery tracking (sends, deliveries,
// bounces, complaints) for one message id.
func (c *SESClient) GetMessageInsights(ctx context.Context, messageID string) (*SESMessageInsightsResponse, error) {
	var out SESMessageInsightsResponse
	path := "/_fakecloud/ses/messages/" + messageID + "/insights"
	if err := c.fc.doGet(ctx, path, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetSmtpSubmissions returns messages received via the inbound SMTP listener
// (FAKECLOUD_SES_SMTP_PORT).
func (c *SESClient) GetSmtpSubmissions(ctx context.Context) (*SESSmtpSubmissionsResponse, error) {
	var out SESSmtpSubmissionsResponse
	if err := c.fc.doGet(ctx, "/_fakecloud/ses/smtp/submissions", &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetEventDestinationDeliveries returns the SES fanout log: every event
// dispatched to a configured event destination (sns/eventbridge/kinesis/firehose/cloudwatch).
func (c *SESClient) GetEventDestinationDeliveries(ctx context.Context) (*SESEventDestinationDeliveriesResponse, error) {
	var out SESEventDestinationDeliveriesResponse
	if err := c.fc.doGet(ctx, "/_fakecloud/ses/event-destinations/deliveries", &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// SetSandbox toggles the SES sandbox state for the account.
// sandbox=true disables production access; sandbox=false re-enables it.
func (c *SESClient) SetSandbox(ctx context.Context, sandbox bool) (*SESSandboxResponse, error) {
	var out SESSandboxResponse
	if err := c.fc.doPost(ctx, "/_fakecloud/ses/account/sandbox", &SESSandboxRequest{Sandbox: sandbox}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
