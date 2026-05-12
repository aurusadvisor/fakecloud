package fakecloud

import "context"

// S3Client provides access to S3 introspection endpoints.
type S3Client struct {
	fc *FakeCloud
}

// GetNotifications lists S3 event notifications.
func (c *S3Client) GetNotifications(ctx context.Context) (*S3NotificationsResponse, error) {
	var out S3NotificationsResponse
	if err := c.fc.doGet(ctx, "/_fakecloud/s3/notifications", &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// TickLifecycle ticks the S3 lifecycle processor.
func (c *S3Client) TickLifecycle(ctx context.Context) (*LifecycleTickResponse, error) {
	var out LifecycleTickResponse
	if err := c.fc.doPost(ctx, "/_fakecloud/s3/lifecycle-processor/tick", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetAccessPoints lists S3 access points across all accounts.
func (c *S3Client) GetAccessPoints(ctx context.Context) (*S3AccessPointsResponse, error) {
	var out S3AccessPointsResponse
	if err := c.fc.doGet(ctx, "/_fakecloud/s3/access-points", &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetObjectLambdaResponses lists stored WriteGetObjectResponse bodies.
func (c *S3Client) GetObjectLambdaResponses(ctx context.Context) (*S3ObjectLambdaResponsesResponse, error) {
	var out S3ObjectLambdaResponsesResponse
	if err := c.fc.doGet(ctx, "/_fakecloud/s3/object-lambda-responses", &out); err != nil {
		return nil, err
	}
	return &out, nil
}
