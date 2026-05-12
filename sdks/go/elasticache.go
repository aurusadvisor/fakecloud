package fakecloud

import "context"

// ElastiCacheClient provides access to ElastiCache introspection endpoints.
type ElastiCacheClient struct {
	fc *FakeCloud
}

// GetClusters lists fakecloud-managed ElastiCache cache clusters and runtime metadata.
func (c *ElastiCacheClient) GetClusters(ctx context.Context) (*ElastiCacheClustersResponse, error) {
	var out ElastiCacheClustersResponse
	if err := c.fc.doGet(ctx, "/_fakecloud/elasticache/clusters", &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetReplicationGroups lists fakecloud-managed ElastiCache replication groups and runtime metadata.
func (c *ElastiCacheClient) GetReplicationGroups(ctx context.Context) (*ElastiCacheReplicationGroupsResponse, error) {
	var out ElastiCacheReplicationGroupsResponse
	if err := c.fc.doGet(ctx, "/_fakecloud/elasticache/replication-groups", &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetServerlessCaches lists fakecloud-managed ElastiCache serverless caches and runtime metadata.
func (c *ElastiCacheClient) GetServerlessCaches(ctx context.Context) (*ElastiCacheServerlessCachesResponse, error) {
	var out ElastiCacheServerlessCachesResponse
	if err := c.fc.doGet(ctx, "/_fakecloud/elasticache/serverless-caches", &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetElastiCacheAcls returns ACL state (users + user groups) for ElastiCache
// replication groups that have one or more user groups attached.
func (c *ElastiCacheClient) GetElastiCacheAcls(ctx context.Context) (*ElastiCacheAclsResponse, error) {
	var out ElastiCacheAclsResponse
	if err := c.fc.doGet(ctx, "/_fakecloud/elasticache/acls", &out); err != nil {
		return nil, err
	}
	return &out, nil
}
