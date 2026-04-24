package fakecloud

import (
	"context"
	"net/url"
)

// ECRClient provides access to ECR introspection endpoints.
type ECRClient struct {
	fc *FakeCloud
}

// GetRepositories lists fakecloud-managed ECR repositories with image and layer counts.
func (c *ECRClient) GetRepositories(ctx context.Context) (*ECRRepositoriesResponse, error) {
	var out ECRRepositoriesResponse
	if err := c.fc.doGet(ctx, "/_fakecloud/ecr/repositories", &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetImages lists stored images across all repositories. Pass a repository name to filter.
func (c *ECRClient) GetImages(ctx context.Context, repo string) (*ECRImagesResponse, error) {
	var out ECRImagesResponse
	path := "/_fakecloud/ecr/images"
	if repo != "" {
		path += "?repo=" + url.QueryEscape(repo)
	}
	if err := c.fc.doGet(ctx, path, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetPullThroughRules lists configured pull-through cache rules.
func (c *ECRClient) GetPullThroughRules(ctx context.Context) (*ECRPullThroughRulesResponse, error) {
	var out ECRPullThroughRulesResponse
	if err := c.fc.doGet(ctx, "/_fakecloud/ecr/pull-through-rules", &out); err != nil {
		return nil, err
	}
	return &out, nil
}
