package fakecloud

import "context"

// LogsClient provides access to CloudWatch Logs admin/introspection endpoints.
type LogsClient struct {
	fc *FakeCloud
}

// InjectAnomaly seeds a synthetic anomaly so tests can exercise
// ListAnomalies/UpdateAnomaly deterministically.
func (c *LogsClient) InjectAnomaly(ctx context.Context, req *LogsAnomalyInjectRequest) (*LogsAnomalyInjectResponse, error) {
	var out LogsAnomalyInjectResponse
	if err := c.fc.doPost(ctx, "/_fakecloud/logs/anomalies/inject", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// LogsAnomalyInjectRequest is the payload for `/_fakecloud/logs/anomalies/inject`.
type LogsAnomalyInjectRequest struct {
	AnomalyDetectorARN string   `json:"anomalyDetectorArn"`
	LogGroupARNs       []string `json:"logGroupArns,omitempty"`
	PatternString      string   `json:"patternString"`
	Priority           *string  `json:"priority,omitempty"`
}

// LogsAnomalyInjectResponse is returned by the inject endpoint.
type LogsAnomalyInjectResponse struct {
	AnomalyID string `json:"anomalyId"`
}
