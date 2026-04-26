//! CloudFront REST-XML service implementation.

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use chrono::Utc;
use http::header::{HeaderName, HeaderValue, ETAG, IF_MATCH, LOCATION};
use http::{HeaderMap, StatusCode};
use parking_lot::RwLock;
use uuid::Uuid;

use fakecloud_core::service::{AwsRequest, AwsResponse, AwsService, AwsServiceError, ResponseBody};

use crate::model::{
    DistributionConfig, DistributionConfigWithTags, InvalidationBatch, TagKeys, Tags as ModelTags,
};
use crate::router::{route, Route};
use crate::state::{
    CloudFrontAccounts, SharedCloudFrontState, StoredDistribution, StoredInvalidation, Tag,
};
use crate::xml_io;

const DEFAULT_ACCOUNT: &str = "000000000000";

const SUPPORTED_ACTIONS: &[&str] = &[
    "CreateDistribution",
    "CreateDistributionWithTags",
    "GetDistribution",
    "GetDistributionConfig",
    "UpdateDistribution",
    "DeleteDistribution",
    "ListDistributions",
    "CopyDistribution",
    "CreateInvalidation",
    "GetInvalidation",
    "ListInvalidations",
    "TagResource",
    "UntagResource",
    "ListTagsForResource",
    "AssociateAlias",
    "ListConflictingAliases",
    "ListDistributionsByCachePolicyId",
    "ListDistributionsByOriginRequestPolicyId",
    "ListDistributionsByResponseHeadersPolicyId",
    "ListDistributionsByKeyGroup",
    "ListDistributionsByWebACLId",
    "ListDistributionsByVpcOriginId",
    "ListDistributionsByAnycastIpListId",
    "ListDistributionsByConnectionMode",
    "ListDistributionsByConnectionFunction",
    "ListDistributionsByOwnedResource",
    "ListDistributionsByTrustStore",
    "ListDistributionsByRealtimeLogConfig",
    "AssociateDistributionWebACL",
    "DisassociateDistributionWebACL",
];

pub struct CloudFrontService {
    state: SharedCloudFrontState,
}

impl CloudFrontService {
    pub fn new(state: SharedCloudFrontState) -> Self {
        Self { state }
    }

    pub fn shared_state(&self) -> SharedCloudFrontState {
        Arc::clone(&self.state)
    }
}

impl Default for CloudFrontService {
    fn default() -> Self {
        Self::new(Arc::new(RwLock::new(CloudFrontAccounts::new())))
    }
}

#[async_trait]
impl AwsService for CloudFrontService {
    fn service_name(&self) -> &str {
        "cloudfront"
    }

    fn supported_actions(&self) -> &[&str] {
        SUPPORTED_ACTIONS
    }

    async fn handle(&self, req: AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let resolved = match route(&req.method, &req.raw_path, &req.raw_query) {
            Some(r) => r,
            None => {
                return Err(aws_error(
                    StatusCode::NOT_FOUND,
                    "InvalidArgument",
                    format!("Unknown CloudFront route: {} {}", req.method, req.raw_path),
                ));
            }
        };

        match resolved.action {
            "CreateDistribution" => self.create_distribution(&req, false),
            "CreateDistributionWithTags" => self.create_distribution(&req, true),
            "GetDistribution" => self.get_distribution(&resolved),
            "GetDistributionConfig" => self.get_distribution_config(&resolved),
            "UpdateDistribution" => self.update_distribution(&req, &resolved),
            "DeleteDistribution" => self.delete_distribution(&req, &resolved),
            "ListDistributions" => self.list_distributions(&req),
            "CopyDistribution" => self.copy_distribution(&req, &resolved),
            "CreateInvalidation" => self.create_invalidation(&req, &resolved),
            "GetInvalidation" => self.get_invalidation(&resolved),
            "ListInvalidations" => self.list_invalidations(&resolved),
            "TagResource" => self.tag_resource(&req),
            "UntagResource" => self.untag_resource(&req),
            "ListTagsForResource" => self.list_tags_for_resource(&req),
            "AssociateAlias" => self.associate_alias(&req, &resolved),
            "ListConflictingAliases" => self.list_conflicting_aliases(&req),
            "AssociateDistributionWebACL" => self.associate_web_acl(&req, &resolved),
            "DisassociateDistributionWebACL" => self.disassociate_web_acl(&req, &resolved),
            "ListDistributionsByCachePolicyId"
            | "ListDistributionsByOriginRequestPolicyId"
            | "ListDistributionsByResponseHeadersPolicyId"
            | "ListDistributionsByKeyGroup"
            | "ListDistributionsByWebACLId"
            | "ListDistributionsByVpcOriginId"
            | "ListDistributionsByAnycastIpListId"
            | "ListDistributionsByConnectionMode"
            | "ListDistributionsByConnectionFunction"
            | "ListDistributionsByOwnedResource"
            | "ListDistributionsByTrustStore"
            | "ListDistributionsByRealtimeLogConfig" => self.list_distributions_by(resolved.action),
            other => Err(aws_error(
                StatusCode::NOT_IMPLEMENTED,
                "InvalidAction",
                format!("CloudFront action {other} is not implemented yet"),
            )),
        }
    }
}

// ─── Distribution handlers ────────────────────────────────────────────

impl CloudFrontService {
    fn create_distribution(
        &self,
        req: &AwsRequest,
        with_tags: bool,
    ) -> Result<AwsResponse, AwsServiceError> {
        let (config, tags) = if with_tags {
            let parsed: DistributionConfigWithTags = xml_io::from_xml_root(&req.body)
                .map_err(|e| invalid_argument(format!("invalid request XML: {e}")))?;
            let tags = parsed
                .tags
                .items
                .map(|i| {
                    i.tag
                        .into_iter()
                        .map(|t| Tag {
                            key: t.key,
                            value: t.value,
                        })
                        .collect()
                })
                .unwrap_or_default();
            (parsed.distribution_config, tags)
        } else {
            let parsed: DistributionConfig = xml_io::from_xml_root(&req.body)
                .map_err(|e| invalid_argument(format!("invalid request XML: {e}")))?;
            (parsed, Vec::new())
        };

        validate_caller_reference(&config.caller_reference)?;
        validate_origins(&config)?;

        let mut state = self.state.write();
        let account = state.entry(account_id(req));

        if let Some(existing) = account
            .distributions
            .values()
            .find(|d| d.config.caller_reference == config.caller_reference)
        {
            return Err(aws_error(
                StatusCode::CONFLICT,
                "DistributionAlreadyExists",
                format!(
                    "Distribution with the same CallerReference exists: {}",
                    existing.id
                ),
            ));
        }

        let id = generate_distribution_id();
        let now = Utc::now();
        let etag = generate_etag();
        let domain = format!("{}.cloudfront.net", id.to_lowercase());
        let arn = format!(
            "arn:aws:cloudfront::{}:distribution/{}",
            account_id(req),
            id
        );

        let stored = StoredDistribution {
            id: id.clone(),
            arn: arn.clone(),
            status: "Deployed".to_string(),
            last_modified_time: now,
            domain_name: domain,
            in_progress_invalidation_batches: 0,
            etag: etag.clone(),
            config,
        };
        account.distributions.insert(id.clone(), stored.clone());
        if !tags.is_empty() {
            account.tags.insert(arn.clone(), tags);
        }
        drop(state);

        let body = build_distribution_xml(&stored);
        let mut headers = HeaderMap::new();
        set_header(&mut headers, ETAG, &etag);
        set_header(&mut headers, LOCATION, &stored.arn);
        Ok(xml_response(StatusCode::CREATED, body, headers))
    }

    fn get_distribution(&self, route: &Route) -> Result<AwsResponse, AwsServiceError> {
        let id = route
            .id
            .as_deref()
            .ok_or_else(|| invalid_argument("missing distribution id"))?;
        let state = self.state.read();
        let account = state
            .accounts
            .get(DEFAULT_ACCOUNT)
            .ok_or_else(|| no_such_distribution(id))?;
        let dist = account
            .distributions
            .get(id)
            .ok_or_else(|| no_such_distribution(id))?
            .clone();
        drop(state);
        let body = build_distribution_xml(&dist);
        let mut headers = HeaderMap::new();
        set_header(&mut headers, ETAG, &dist.etag);
        Ok(xml_response(StatusCode::OK, body, headers))
    }

    fn get_distribution_config(&self, route: &Route) -> Result<AwsResponse, AwsServiceError> {
        let id = route
            .id
            .as_deref()
            .ok_or_else(|| invalid_argument("missing distribution id"))?;
        let state = self.state.read();
        let account = state
            .accounts
            .get(DEFAULT_ACCOUNT)
            .ok_or_else(|| no_such_distribution(id))?;
        let dist = account
            .distributions
            .get(id)
            .ok_or_else(|| no_such_distribution(id))?
            .clone();
        drop(state);
        let body = xml_io::to_xml_root("DistributionConfig", &dist.config)
            .map_err(|e| internal_error(format!("xml encode failed: {e}")))?;
        let mut headers = HeaderMap::new();
        set_header(&mut headers, ETAG, &dist.etag);
        Ok(xml_response(StatusCode::OK, body, headers))
    }

    fn update_distribution(
        &self,
        req: &AwsRequest,
        route: &Route,
    ) -> Result<AwsResponse, AwsServiceError> {
        let id = route
            .id
            .as_deref()
            .ok_or_else(|| invalid_argument("missing distribution id"))?;
        let if_match = req
            .headers
            .get(IF_MATCH)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| {
                aws_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidIfMatchVersion",
                    "Missing If-Match header for UpdateDistribution",
                )
            })?
            .to_string();
        let new_config: DistributionConfig = xml_io::from_xml_root(&req.body)
            .map_err(|e| invalid_argument(format!("invalid DistributionConfig XML: {e}")))?;
        validate_caller_reference(&new_config.caller_reference)?;
        validate_origins(&new_config)?;

        let mut state = self.state.write();
        let account = state
            .accounts
            .get_mut(DEFAULT_ACCOUNT)
            .ok_or_else(|| no_such_distribution(id))?;
        let dist = account
            .distributions
            .get_mut(id)
            .ok_or_else(|| no_such_distribution(id))?;
        if dist.etag != if_match {
            return Err(aws_error(
                StatusCode::PRECONDITION_FAILED,
                "PreconditionFailed",
                "If-Match header does not match the current ETag",
            ));
        }
        dist.config = new_config;
        dist.etag = generate_etag();
        dist.last_modified_time = Utc::now();
        let snapshot = dist.clone();
        drop(state);

        let body = build_distribution_xml(&snapshot);
        let mut headers = HeaderMap::new();
        set_header(&mut headers, ETAG, &snapshot.etag);
        Ok(xml_response(StatusCode::OK, body, headers))
    }

    fn delete_distribution(
        &self,
        req: &AwsRequest,
        route: &Route,
    ) -> Result<AwsResponse, AwsServiceError> {
        let id = route
            .id
            .as_deref()
            .ok_or_else(|| invalid_argument("missing distribution id"))?;
        let if_match = req
            .headers
            .get(IF_MATCH)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| {
                aws_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidIfMatchVersion",
                    "Missing If-Match header for DeleteDistribution",
                )
            })?
            .to_string();
        let mut state = self.state.write();
        let account = state
            .accounts
            .get_mut(DEFAULT_ACCOUNT)
            .ok_or_else(|| no_such_distribution(id))?;
        {
            let dist = account
                .distributions
                .get(id)
                .ok_or_else(|| no_such_distribution(id))?;
            if dist.etag != if_match {
                return Err(aws_error(
                    StatusCode::PRECONDITION_FAILED,
                    "PreconditionFailed",
                    "If-Match header does not match the current ETag",
                ));
            }
            if dist.config.enabled {
                return Err(aws_error(
                    StatusCode::PRECONDITION_FAILED,
                    "DistributionNotDisabled",
                    "Distribution must be disabled before delete",
                ));
            }
        }
        let removed = account.distributions.remove(id).unwrap();
        account.tags.remove(&removed.arn);
        Ok(empty_response(StatusCode::NO_CONTENT))
    }

    fn list_distributions(&self, _req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let state = self.state.read();
        let mut dists: Vec<StoredDistribution> = state
            .accounts
            .values()
            .flat_map(|a| a.distributions.values().cloned())
            .collect();
        dists.sort_by_key(|a| a.last_modified_time);
        drop(state);
        let body = build_distribution_list_xml(&dists, "DistributionList");
        Ok(xml_response(StatusCode::OK, body, HeaderMap::new()))
    }

    fn list_distributions_by(&self, action: &str) -> Result<AwsResponse, AwsServiceError> {
        // The "by-X" listings each have a distinct response root element.
        // We never index distributions by the predicate (that would require
        // shipping each policy/key-group/etc service first), so each
        // response is empty until those services land.
        let root = match action {
            "ListDistributionsByCachePolicyId"
            | "ListDistributionsByOriginRequestPolicyId"
            | "ListDistributionsByResponseHeadersPolicyId"
            | "ListDistributionsByKeyGroup"
            | "ListDistributionsByWebACLId"
            | "ListDistributionsByVpcOriginId"
            | "ListDistributionsByAnycastIpListId"
            | "ListDistributionsByRealtimeLogConfig"
            | "ListDistributionsByTrustStore"
            | "ListDistributionsByConnectionMode"
            | "ListDistributionsByConnectionFunction" => "DistributionIdList",
            "ListDistributionsByOwnedResource" => "DistributionList",
            _ => "DistributionList",
        };
        let body = build_empty_distribution_id_list(root);
        Ok(xml_response(StatusCode::OK, body, HeaderMap::new()))
    }

    fn copy_distribution(
        &self,
        req: &AwsRequest,
        route: &Route,
    ) -> Result<AwsResponse, AwsServiceError> {
        let primary_id = route
            .id
            .as_deref()
            .ok_or_else(|| invalid_argument("missing primary distribution id"))?;
        let if_match = req
            .headers
            .get(IF_MATCH)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| {
                aws_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidIfMatchVersion",
                    "Missing If-Match header for CopyDistribution",
                )
            })?
            .to_string();
        let parsed: CopyDistributionRequest = xml_io::from_xml_root(&req.body)
            .map_err(|e| invalid_argument(format!("invalid request XML: {e}")))?;
        let mut state = self.state.write();
        let account = state
            .accounts
            .get_mut(DEFAULT_ACCOUNT)
            .ok_or_else(|| no_such_distribution(primary_id))?;
        let primary = account
            .distributions
            .get(primary_id)
            .ok_or_else(|| no_such_distribution(primary_id))?
            .clone();
        if primary.etag != if_match {
            return Err(aws_error(
                StatusCode::PRECONDITION_FAILED,
                "PreconditionFailed",
                "If-Match header does not match the current ETag",
            ));
        }
        if account
            .distributions
            .values()
            .any(|d| d.config.caller_reference == parsed.caller_reference)
        {
            return Err(aws_error(
                StatusCode::CONFLICT,
                "DistributionAlreadyExists",
                "Distribution with the same CallerReference exists",
            ));
        }
        let new_id = generate_distribution_id();
        let mut config = primary.config.clone();
        config.caller_reference = parsed.caller_reference;
        config.enabled = parsed.enabled.unwrap_or(false);
        config.staging = parsed.staging;
        let now = Utc::now();
        let etag = generate_etag();
        let arn = format!(
            "arn:aws:cloudfront::{}:distribution/{}",
            account_id(req),
            new_id
        );
        let stored = StoredDistribution {
            id: new_id.clone(),
            arn: arn.clone(),
            status: "Deployed".into(),
            last_modified_time: now,
            domain_name: format!("{}.cloudfront.net", new_id.to_lowercase()),
            in_progress_invalidation_batches: 0,
            etag: etag.clone(),
            config,
        };
        account.distributions.insert(new_id.clone(), stored.clone());
        drop(state);
        let body = build_distribution_xml(&stored);
        let mut headers = HeaderMap::new();
        set_header(&mut headers, ETAG, &etag);
        set_header(&mut headers, LOCATION, &stored.arn);
        Ok(xml_response(StatusCode::CREATED, body, headers))
    }
}

#[derive(Debug, serde::Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
struct CopyDistributionRequest {
    caller_reference: String,
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    staging: Option<bool>,
}

// ─── Invalidations ────────────────────────────────────────────────────

impl CloudFrontService {
    fn create_invalidation(
        &self,
        req: &AwsRequest,
        route: &Route,
    ) -> Result<AwsResponse, AwsServiceError> {
        let dist_id = route
            .id
            .as_deref()
            .ok_or_else(|| invalid_argument("missing distribution id"))?;
        let batch: InvalidationBatch = xml_io::from_xml_root(&req.body)
            .map_err(|e| invalid_argument(format!("invalid InvalidationBatch XML: {e}")))?;
        if batch.caller_reference.is_empty() {
            return Err(invalid_argument("CallerReference is required"));
        }
        if batch.paths.quantity < 1 {
            return Err(invalid_argument(
                "InvalidationBatch.Paths must be non-empty",
            ));
        }
        let mut state = self.state.write();
        let account = state.entry(DEFAULT_ACCOUNT);
        if !account.distributions.contains_key(dist_id) {
            return Err(no_such_distribution(dist_id));
        }
        let id = generate_invalidation_id();
        let stored = StoredInvalidation {
            id: id.clone(),
            distribution_id: dist_id.to_string(),
            status: "Completed".to_string(),
            create_time: Utc::now(),
            batch: batch.clone(),
        };
        account.invalidations.insert(id.clone(), stored.clone());
        drop(state);
        let body = build_invalidation_xml(&stored);
        let mut headers = HeaderMap::new();
        set_header(
            &mut headers,
            LOCATION,
            &format!(
                "/2020-05-31/distribution/{dist_id}/invalidation/{}",
                stored.id
            ),
        );
        Ok(xml_response(StatusCode::CREATED, body, headers))
    }

    fn get_invalidation(&self, route: &Route) -> Result<AwsResponse, AwsServiceError> {
        let dist_id = route
            .id
            .as_deref()
            .ok_or_else(|| invalid_argument("missing distribution id"))?;
        let inv_id = route
            .second_id
            .as_deref()
            .ok_or_else(|| invalid_argument("missing invalidation id"))?;
        let state = self.state.read();
        let account = state
            .accounts
            .get(DEFAULT_ACCOUNT)
            .ok_or_else(|| no_such_invalidation(inv_id))?;
        if !account.distributions.contains_key(dist_id) {
            return Err(no_such_distribution(dist_id));
        }
        let inv = account
            .invalidations
            .get(inv_id)
            .filter(|i| i.distribution_id == dist_id)
            .ok_or_else(|| no_such_invalidation(inv_id))?
            .clone();
        drop(state);
        let body = build_invalidation_xml(&inv);
        Ok(xml_response(StatusCode::OK, body, HeaderMap::new()))
    }

    fn list_invalidations(&self, route: &Route) -> Result<AwsResponse, AwsServiceError> {
        let dist_id = route
            .id
            .as_deref()
            .ok_or_else(|| invalid_argument("missing distribution id"))?;
        let state = self.state.read();
        let account = state
            .accounts
            .get(DEFAULT_ACCOUNT)
            .ok_or_else(|| no_such_distribution(dist_id))?;
        if !account.distributions.contains_key(dist_id) {
            return Err(no_such_distribution(dist_id));
        }
        let mut items: Vec<&StoredInvalidation> = account
            .invalidations
            .values()
            .filter(|i| i.distribution_id == dist_id)
            .collect();
        items.sort_by_key(|a| a.create_time);
        let body = build_invalidation_list_xml(&items);
        drop(state);
        Ok(xml_response(StatusCode::OK, body, HeaderMap::new()))
    }
}

// ─── Tags ─────────────────────────────────────────────────────────────

impl CloudFrontService {
    fn parse_arn_query(query: &str) -> Option<String> {
        for pair in query.split('&').filter(|p| !p.is_empty()) {
            if let Some(rest) = pair.strip_prefix("Resource=") {
                return Some(percent_decode(rest));
            }
        }
        None
    }

    fn tag_resource(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let arn = Self::parse_arn_query(&req.raw_query)
            .ok_or_else(|| invalid_argument("Resource query parameter is required"))?;
        let parsed: ModelTags = xml_io::from_xml_root(&req.body)
            .map_err(|e| invalid_argument(format!("invalid Tags XML: {e}")))?;
        let new_tags: Vec<Tag> = parsed
            .items
            .map(|i| {
                i.tag
                    .into_iter()
                    .map(|t| Tag {
                        key: t.key,
                        value: t.value,
                    })
                    .collect()
            })
            .unwrap_or_default();
        let mut state = self.state.write();
        let account = state.entry(DEFAULT_ACCOUNT);
        let entry = account.tags.entry(arn).or_default();
        for tag in new_tags {
            if let Some(existing) = entry.iter_mut().find(|t| t.key == tag.key) {
                existing.value = tag.value;
            } else {
                entry.push(tag);
            }
        }
        Ok(empty_response(StatusCode::NO_CONTENT))
    }

    fn untag_resource(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let arn = Self::parse_arn_query(&req.raw_query)
            .ok_or_else(|| invalid_argument("Resource query parameter is required"))?;
        let parsed: TagKeys = xml_io::from_xml_root(&req.body)
            .map_err(|e| invalid_argument(format!("invalid TagKeys XML: {e}")))?;
        let keys: Vec<String> = parsed.items.map(|k| k.key).unwrap_or_default();
        let mut state = self.state.write();
        let account = state.entry(DEFAULT_ACCOUNT);
        if let Some(existing) = account.tags.get_mut(&arn) {
            existing.retain(|t| !keys.contains(&t.key));
        }
        Ok(empty_response(StatusCode::NO_CONTENT))
    }

    fn list_tags_for_resource(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let arn = Self::parse_arn_query(&req.raw_query)
            .ok_or_else(|| invalid_argument("Resource query parameter is required"))?;
        let state = self.state.read();
        let tags = state
            .accounts
            .get(DEFAULT_ACCOUNT)
            .and_then(|a| a.tags.get(&arn))
            .cloned()
            .unwrap_or_default();
        drop(state);
        let body = build_tags_xml(&tags);
        Ok(xml_response(StatusCode::OK, body, HeaderMap::new()))
    }
}

// ─── Aliases / WebACL ─────────────────────────────────────────────────

impl CloudFrontService {
    fn associate_alias(
        &self,
        req: &AwsRequest,
        route: &Route,
    ) -> Result<AwsResponse, AwsServiceError> {
        let id = route
            .id
            .as_deref()
            .ok_or_else(|| invalid_argument("missing distribution id"))?;
        let alias = parse_query_value(&req.raw_query, "Alias")
            .ok_or_else(|| invalid_argument("Alias query parameter is required"))?;
        let mut state = self.state.write();
        let account = state
            .accounts
            .get_mut(DEFAULT_ACCOUNT)
            .ok_or_else(|| no_such_distribution(id))?;
        // Reject if the alias is already attached to a different distribution.
        if let Some(other) = account.distributions.values().find(|d| {
            d.id != id
                && d.config
                    .aliases
                    .as_ref()
                    .and_then(|a| a.items.as_ref())
                    .is_some_and(|i| i.cname.iter().any(|c| c == &alias))
        }) {
            return Err(aws_error(
                StatusCode::CONFLICT,
                "CNAMEAlreadyExists",
                format!(
                    "Alias {alias} is already associated with distribution {}",
                    other.id
                ),
            ));
        }
        let dist = account
            .distributions
            .get_mut(id)
            .ok_or_else(|| no_such_distribution(id))?;
        let aliases = dist.config.aliases.get_or_insert_with(Default::default);
        let items = aliases
            .items
            .get_or_insert_with(crate::model::AliasItems::default);
        if !items.cname.iter().any(|c| c == &alias) {
            items.cname.push(alias.clone());
            aliases.quantity = items.cname.len() as i32;
        }
        dist.etag = generate_etag();
        dist.last_modified_time = Utc::now();
        Ok(empty_response(StatusCode::OK))
    }

    fn list_conflicting_aliases(&self, _req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        // We never produce conflicts because every alias is owned by one
        // distribution at most. Return an empty list with the proper shape.
        let body = format!(
            "{XML_DECL}<ConflictingAliasesList xmlns=\"{NS}\"><Quantity>0</Quantity></ConflictingAliasesList>",
            NS = crate::NAMESPACE,
            XML_DECL = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        );
        Ok(xml_response(StatusCode::OK, body, HeaderMap::new()))
    }

    fn associate_web_acl(
        &self,
        req: &AwsRequest,
        route: &Route,
    ) -> Result<AwsResponse, AwsServiceError> {
        let id = route
            .id
            .as_deref()
            .ok_or_else(|| invalid_argument("missing distribution id"))?;
        let parsed: AssociateAliasRequest = xml_io::from_xml_root(&req.body)
            .map_err(|e| invalid_argument(format!("invalid request XML: {e}")))?;
        let mut state = self.state.write();
        let account = state
            .accounts
            .get_mut(DEFAULT_ACCOUNT)
            .ok_or_else(|| no_such_distribution(id))?;
        let dist = account
            .distributions
            .get_mut(id)
            .ok_or_else(|| no_such_distribution(id))?;
        dist.config.web_acl_id = Some(parsed.web_acl_arn.clone());
        dist.etag = generate_etag();
        dist.last_modified_time = Utc::now();
        let body = format!(
            "{XML_DECL}<AssociateDistributionWebACLResult xmlns=\"{NS}\"><Id>{}</Id><WebACLArn>{}</WebACLArn></AssociateDistributionWebACLResult>",
            id, parsed.web_acl_arn,
            NS = crate::NAMESPACE,
            XML_DECL = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        );
        Ok(xml_response(StatusCode::OK, body, HeaderMap::new()))
    }

    fn disassociate_web_acl(
        &self,
        _req: &AwsRequest,
        route: &Route,
    ) -> Result<AwsResponse, AwsServiceError> {
        let id = route
            .id
            .as_deref()
            .ok_or_else(|| invalid_argument("missing distribution id"))?;
        let mut state = self.state.write();
        let account = state
            .accounts
            .get_mut(DEFAULT_ACCOUNT)
            .ok_or_else(|| no_such_distribution(id))?;
        let dist = account
            .distributions
            .get_mut(id)
            .ok_or_else(|| no_such_distribution(id))?;
        dist.config.web_acl_id = None;
        dist.etag = generate_etag();
        dist.last_modified_time = Utc::now();
        let body = format!(
            "{XML_DECL}<DisassociateDistributionWebACLResult xmlns=\"{NS}\"><Id>{}</Id></DisassociateDistributionWebACLResult>",
            id,
            NS = crate::NAMESPACE,
            XML_DECL = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        );
        Ok(xml_response(StatusCode::OK, body, HeaderMap::new()))
    }
}

#[derive(serde::Deserialize, Default, Debug)]
#[serde(rename_all = "PascalCase")]
struct AssociateAliasRequest {
    #[serde(rename = "WebACLArn", default)]
    web_acl_arn: String,
}

// ─── XML body builders ────────────────────────────────────────────────

fn build_distribution_xml(dist: &StoredDistribution) -> String {
    let mut out = String::with_capacity(2048);
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
    out.push_str(&format!(
        "<Distribution xmlns=\"{ns}\">",
        ns = crate::NAMESPACE
    ));
    out.push_str(&format!("<Id>{}</Id>", dist.id));
    out.push_str(&format!("<ARN>{}</ARN>", dist.arn));
    out.push_str(&format!("<Status>{}</Status>", dist.status));
    out.push_str(&format!(
        "<LastModifiedTime>{}</LastModifiedTime>",
        rfc3339(&dist.last_modified_time)
    ));
    out.push_str(&format!(
        "<InProgressInvalidationBatches>{}</InProgressInvalidationBatches>",
        dist.in_progress_invalidation_batches
    ));
    out.push_str(&format!("<DomainName>{}</DomainName>", dist.domain_name));
    out.push_str("<ActiveTrustedSigners><Enabled>false</Enabled><Quantity>0</Quantity></ActiveTrustedSigners>");
    out.push_str("<ActiveTrustedKeyGroups><Enabled>false</Enabled><Quantity>0</Quantity></ActiveTrustedKeyGroups>");
    let inner = quick_xml::se::to_string_with_root("DistributionConfig", &dist.config)
        .unwrap_or_else(|_| String::new());
    out.push_str(&inner);
    out.push_str("</Distribution>");
    out
}

fn build_distribution_list_xml(dists: &[StoredDistribution], root: &str) -> String {
    let mut out = String::with_capacity(2048);
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
    out.push_str(&format!("<{root} xmlns=\"{ns}\">", ns = crate::NAMESPACE));
    out.push_str("<Marker></Marker>");
    out.push_str(&format!("<MaxItems>{}</MaxItems>", dists.len().max(100)));
    out.push_str("<IsTruncated>false</IsTruncated>");
    out.push_str(&format!("<Quantity>{}</Quantity>", dists.len()));
    if dists.is_empty() {
        out.push_str(&format!("</{root}>"));
        return out;
    }
    out.push_str("<Items>");
    for d in dists {
        out.push_str("<DistributionSummary>");
        out.push_str(&format!("<Id>{}</Id>", d.id));
        out.push_str(&format!("<ARN>{}</ARN>", d.arn));
        out.push_str(&format!("<Status>{}</Status>", d.status));
        out.push_str(&format!(
            "<LastModifiedTime>{}</LastModifiedTime>",
            rfc3339(&d.last_modified_time)
        ));
        out.push_str(&format!("<DomainName>{}</DomainName>", d.domain_name));
        let aliases = d.config.aliases.clone().unwrap_or_default();
        out.push_str(&render_inline("Aliases", &aliases));
        let origins = d.config.origins.clone();
        out.push_str(&render_inline("Origins", &origins));
        let dcb = d.config.default_cache_behavior.clone();
        out.push_str(&render_inline("DefaultCacheBehavior", &dcb));
        let cb = d.config.cache_behaviors.clone().unwrap_or_default();
        out.push_str(&render_inline("CacheBehaviors", &cb));
        let cer = d.config.custom_error_responses.clone().unwrap_or_default();
        out.push_str(&render_inline("CustomErrorResponses", &cer));
        out.push_str(&format!("<Comment>{}</Comment>", d.config.comment));
        out.push_str(&format!(
            "<PriceClass>{}</PriceClass>",
            d.config
                .price_class
                .clone()
                .unwrap_or_else(|| "PriceClass_All".to_string())
        ));
        out.push_str(&format!("<Enabled>{}</Enabled>", d.config.enabled));
        out.push_str(&render_inline(
            "ViewerCertificate",
            &d.config.viewer_certificate.clone().unwrap_or_default(),
        ));
        out.push_str(&render_inline(
            "Restrictions",
            &d.config.restrictions.clone().unwrap_or_default(),
        ));
        out.push_str(&format!(
            "<WebACLId>{}</WebACLId>",
            d.config.web_acl_id.clone().unwrap_or_default()
        ));
        out.push_str(&format!(
            "<HttpVersion>{}</HttpVersion>",
            d.config
                .http_version
                .clone()
                .unwrap_or_else(|| "http2".to_string())
        ));
        out.push_str(&format!(
            "<IsIPV6Enabled>{}</IsIPV6Enabled>",
            d.config.is_ipv6_enabled.unwrap_or(true)
        ));
        out.push_str("<Staging>false</Staging>");
        out.push_str("</DistributionSummary>");
    }
    out.push_str("</Items>");
    out.push_str(&format!("</{root}>"));
    out
}

fn build_empty_distribution_id_list(root: &str) -> String {
    let mut out = String::with_capacity(256);
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
    out.push_str(&format!("<{root} xmlns=\"{ns}\">", ns = crate::NAMESPACE));
    out.push_str("<Marker></Marker>");
    out.push_str("<MaxItems>100</MaxItems>");
    out.push_str("<IsTruncated>false</IsTruncated>");
    out.push_str("<Quantity>0</Quantity>");
    out.push_str(&format!("</{root}>"));
    out
}

fn build_invalidation_xml(inv: &StoredInvalidation) -> String {
    let mut out = String::with_capacity(512);
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
    out.push_str(&format!(
        "<Invalidation xmlns=\"{ns}\">",
        ns = crate::NAMESPACE
    ));
    out.push_str(&format!("<Id>{}</Id>", inv.id));
    out.push_str(&format!("<Status>{}</Status>", inv.status));
    out.push_str(&format!(
        "<CreateTime>{}</CreateTime>",
        rfc3339(&inv.create_time)
    ));
    out.push_str(&render_inline("InvalidationBatch", &inv.batch));
    out.push_str("</Invalidation>");
    out
}

fn build_invalidation_list_xml(items: &[&StoredInvalidation]) -> String {
    let mut out = String::with_capacity(1024);
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
    out.push_str(&format!(
        "<InvalidationList xmlns=\"{ns}\">",
        ns = crate::NAMESPACE
    ));
    out.push_str("<Marker></Marker>");
    out.push_str("<MaxItems>100</MaxItems>");
    out.push_str("<IsTruncated>false</IsTruncated>");
    out.push_str(&format!("<Quantity>{}</Quantity>", items.len()));
    if !items.is_empty() {
        out.push_str("<Items>");
        for inv in items {
            out.push_str("<InvalidationSummary>");
            out.push_str(&format!("<Id>{}</Id>", inv.id));
            out.push_str(&format!(
                "<CreateTime>{}</CreateTime>",
                rfc3339(&inv.create_time)
            ));
            out.push_str(&format!("<Status>{}</Status>", inv.status));
            out.push_str("</InvalidationSummary>");
        }
        out.push_str("</Items>");
    }
    out.push_str("</InvalidationList>");
    out
}

fn build_tags_xml(tags: &[Tag]) -> String {
    let mut out = String::with_capacity(256);
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
    out.push_str(&format!("<Tags xmlns=\"{ns}\">", ns = crate::NAMESPACE));
    out.push_str("<Items>");
    for t in tags {
        out.push_str("<Tag>");
        out.push_str(&format!("<Key>{}</Key>", t.key));
        if let Some(v) = &t.value {
            out.push_str(&format!("<Value>{v}</Value>"));
        }
        out.push_str("</Tag>");
    }
    out.push_str("</Items>");
    out.push_str("</Tags>");
    out
}

fn render_inline<T: serde::Serialize>(root: &str, value: &T) -> String {
    quick_xml::se::to_string_with_root(root, value).unwrap_or_default()
}

// ─── Helpers ──────────────────────────────────────────────────────────

fn validate_caller_reference(s: &str) -> Result<(), AwsServiceError> {
    if s.is_empty() {
        return Err(invalid_argument("CallerReference is required"));
    }
    Ok(())
}

fn validate_origins(config: &DistributionConfig) -> Result<(), AwsServiceError> {
    if config.origins.quantity < 1 {
        return Err(invalid_argument(
            "DistributionConfig.Origins must contain at least one origin",
        ));
    }
    Ok(())
}

fn account_id(_req: &AwsRequest) -> &'static str {
    // Multi-account is wired through AwsRequest.account_id elsewhere; the
    // CloudFront control plane only uses the resolved id for the ARN
    // suffix. Until that field stabilizes for REST-XML we use the default
    // account ID consistently with the rest of the registered services.
    DEFAULT_ACCOUNT
}

fn generate_distribution_id() -> String {
    // CloudFront IDs are 14-char base32-ish uppercase strings starting with E.
    let raw = Uuid::new_v4().simple().to_string().to_uppercase();
    format!("E{}", &raw[..13])
}

fn generate_invalidation_id() -> String {
    let raw = Uuid::new_v4().simple().to_string().to_uppercase();
    format!("I{}", &raw[..13])
}

fn generate_etag() -> String {
    let raw = Uuid::new_v4().simple().to_string().to_uppercase();
    format!("E{}", &raw[..13])
}

fn rfc3339(t: &chrono::DateTime<chrono::Utc>) -> String {
    t.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn invalid_argument(msg: impl Into<String>) -> AwsServiceError {
    aws_error(StatusCode::BAD_REQUEST, "InvalidArgument", msg)
}

fn no_such_distribution(id: &str) -> AwsServiceError {
    aws_error(
        StatusCode::NOT_FOUND,
        "NoSuchDistribution",
        format!("The specified distribution does not exist: {id}"),
    )
}

fn no_such_invalidation(id: &str) -> AwsServiceError {
    aws_error(
        StatusCode::NOT_FOUND,
        "NoSuchInvalidation",
        format!("The specified invalidation does not exist: {id}"),
    )
}

fn internal_error(msg: impl Into<String>) -> AwsServiceError {
    aws_error(StatusCode::INTERNAL_SERVER_ERROR, "InternalError", msg)
}

fn aws_error(status: StatusCode, code: &str, msg: impl Into<String>) -> AwsServiceError {
    AwsServiceError::aws_error(status, code, msg)
}

fn set_header(headers: &mut HeaderMap, name: HeaderName, value: &str) {
    if let Ok(v) = HeaderValue::from_str(value) {
        headers.insert(name, v);
    }
}

fn xml_response(status: StatusCode, body: String, headers: HeaderMap) -> AwsResponse {
    AwsResponse {
        status,
        content_type: "text/xml".to_string(),
        body: ResponseBody::Bytes(Bytes::from(body)),
        headers,
    }
}

fn empty_response(status: StatusCode) -> AwsResponse {
    AwsResponse {
        status,
        content_type: "text/xml".to_string(),
        body: ResponseBody::Bytes(Bytes::new()),
        headers: HeaderMap::new(),
    }
}

fn percent_decode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'%' && i + 2 < bytes.len() {
            if let (Some(a), Some(c)) = (hex_digit(bytes[i + 1]), hex_digit(bytes[i + 2])) {
                out.push(((a << 4) | c) as char);
                i += 3;
                continue;
            }
        }
        if b == b'+' {
            out.push(' ');
        } else {
            out.push(b as char);
        }
        i += 1;
    }
    out
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn parse_query_value(query: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}=");
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        if let Some(rest) = pair.strip_prefix(&prefix) {
            return Some(percent_decode(rest));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_state() -> SharedCloudFrontState {
        Arc::new(RwLock::new(CloudFrontAccounts::new()))
    }

    fn make_request(method: http::Method, path: &str, query: &str, body: &str) -> AwsRequest {
        AwsRequest {
            service: "cloudfront".into(),
            action: String::new(),
            region: "us-east-1".into(),
            account_id: DEFAULT_ACCOUNT.into(),
            request_id: Uuid::new_v4().to_string(),
            headers: HeaderMap::new(),
            query_params: std::collections::HashMap::new(),
            body_stream: parking_lot::Mutex::new(None),
            body: Bytes::from(body.to_string()),
            path_segments: path
                .split('/')
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect(),
            raw_path: path.into(),
            raw_query: query.into(),
            method,
            is_query_protocol: false,
            access_key_id: None,
            principal: None,
        }
    }

    fn minimal_dist_config_xml(caller_ref: &str) -> String {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<DistributionConfig xmlns="http://cloudfront.amazonaws.com/doc/2020-05-31/">
  <CallerReference>{caller_ref}</CallerReference>
  <Origins>
    <Quantity>1</Quantity>
    <Items>
      <Origin>
        <Id>primary</Id>
        <DomainName>example.com</DomainName>
      </Origin>
    </Items>
  </Origins>
  <DefaultCacheBehavior>
    <TargetOriginId>primary</TargetOriginId>
    <ViewerProtocolPolicy>allow-all</ViewerProtocolPolicy>
  </DefaultCacheBehavior>
  <Comment></Comment>
  <Enabled>true</Enabled>
</DistributionConfig>"#
        )
    }

    #[tokio::test]
    async fn create_then_get_then_delete_distribution() {
        let svc = CloudFrontService::new(make_state());
        let body = minimal_dist_config_xml("ref-1");
        let create = svc
            .handle(make_request(
                http::Method::POST,
                "/2020-05-31/distribution",
                "",
                &body,
            ))
            .await
            .unwrap();
        assert_eq!(create.status, StatusCode::CREATED);
        let etag = create
            .headers
            .get(ETAG)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let xml = std::str::from_utf8(create.body.expect_bytes()).unwrap();
        let id = xml
            .split("<Id>")
            .nth(1)
            .unwrap()
            .split("</Id>")
            .next()
            .unwrap()
            .to_string();

        let get = svc
            .handle(make_request(
                http::Method::GET,
                &format!("/2020-05-31/distribution/{id}"),
                "",
                "",
            ))
            .await
            .unwrap();
        assert_eq!(get.status, StatusCode::OK);

        // Disable then delete (CloudFront requires Disabled before delete).
        let disable_body = body.replace("<Enabled>true</Enabled>", "<Enabled>false</Enabled>");
        let mut update_req = make_request(
            http::Method::PUT,
            &format!("/2020-05-31/distribution/{id}/config"),
            "",
            &disable_body,
        );
        update_req.headers.insert(IF_MATCH, etag.parse().unwrap());
        let updated = svc.handle(update_req).await.unwrap();
        assert_eq!(updated.status, StatusCode::OK);
        let new_etag = updated
            .headers
            .get(ETAG)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();

        let mut del_req = make_request(
            http::Method::DELETE,
            &format!("/2020-05-31/distribution/{id}"),
            "",
            "",
        );
        del_req.headers.insert(IF_MATCH, new_etag.parse().unwrap());
        let del = svc.handle(del_req).await.unwrap();
        assert_eq!(del.status, StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn duplicate_caller_reference_is_rejected() {
        let svc = CloudFrontService::new(make_state());
        let body = minimal_dist_config_xml("dup-ref");
        svc.handle(make_request(
            http::Method::POST,
            "/2020-05-31/distribution",
            "",
            &body,
        ))
        .await
        .unwrap();
        let result = svc
            .handle(make_request(
                http::Method::POST,
                "/2020-05-31/distribution",
                "",
                &body,
            ))
            .await;
        let err = match result {
            Ok(_) => panic!("expected duplicate caller-reference to fail"),
            Err(e) => e,
        };
        assert_eq!(err.code(), "DistributionAlreadyExists");
        assert_eq!(err.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn invalidation_lifecycle() {
        let svc = CloudFrontService::new(make_state());
        let body = minimal_dist_config_xml("inv-ref");
        let create = svc
            .handle(make_request(
                http::Method::POST,
                "/2020-05-31/distribution",
                "",
                &body,
            ))
            .await
            .unwrap();
        let xml = std::str::from_utf8(create.body.expect_bytes()).unwrap();
        let dist_id = xml
            .split("<Id>")
            .nth(1)
            .unwrap()
            .split("</Id>")
            .next()
            .unwrap();
        let inv_body = r#"<?xml version="1.0" encoding="UTF-8"?>
<InvalidationBatch xmlns="http://cloudfront.amazonaws.com/doc/2020-05-31/">
  <Paths><Quantity>1</Quantity><Items><Path>/*</Path></Items></Paths>
  <CallerReference>inv-1</CallerReference>
</InvalidationBatch>"#;
        let inv_resp = svc
            .handle(make_request(
                http::Method::POST,
                &format!("/2020-05-31/distribution/{dist_id}/invalidation"),
                "",
                inv_body,
            ))
            .await
            .unwrap();
        assert_eq!(inv_resp.status, StatusCode::CREATED);
        let inv_xml = std::str::from_utf8(inv_resp.body.expect_bytes()).unwrap();
        let inv_id = inv_xml
            .split("<Id>")
            .nth(1)
            .unwrap()
            .split("</Id>")
            .next()
            .unwrap();
        let get = svc
            .handle(make_request(
                http::Method::GET,
                &format!("/2020-05-31/distribution/{dist_id}/invalidation/{inv_id}"),
                "",
                "",
            ))
            .await
            .unwrap();
        assert_eq!(get.status, StatusCode::OK);
        let list = svc
            .handle(make_request(
                http::Method::GET,
                &format!("/2020-05-31/distribution/{dist_id}/invalidation"),
                "",
                "",
            ))
            .await
            .unwrap();
        let xml = std::str::from_utf8(list.body.expect_bytes()).unwrap();
        assert!(xml.contains("<Quantity>1</Quantity>"));
    }

    #[tokio::test]
    async fn tags_roundtrip() {
        let svc = CloudFrontService::new(make_state());
        let body = minimal_dist_config_xml("tag-ref");
        let create = svc
            .handle(make_request(
                http::Method::POST,
                "/2020-05-31/distribution",
                "",
                &body,
            ))
            .await
            .unwrap();
        let xml = std::str::from_utf8(create.body.expect_bytes()).unwrap();
        let arn = xml
            .split("<ARN>")
            .nth(1)
            .unwrap()
            .split("</ARN>")
            .next()
            .unwrap();
        let tag_body = r#"<?xml version="1.0" encoding="UTF-8"?>
<Tags xmlns="http://cloudfront.amazonaws.com/doc/2020-05-31/">
  <Items><Tag><Key>env</Key><Value>prod</Value></Tag></Items>
</Tags>"#;
        let arn_q = format!("Operation=Tag&Resource={}", arn);
        let resp = svc
            .handle(make_request(
                http::Method::POST,
                "/2020-05-31/tagging",
                &arn_q,
                tag_body,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status, StatusCode::NO_CONTENT);
        let list = svc
            .handle(make_request(
                http::Method::GET,
                "/2020-05-31/tagging",
                &format!("Resource={}", arn),
                "",
            ))
            .await
            .unwrap();
        let xml = std::str::from_utf8(list.body.expect_bytes()).unwrap();
        assert!(xml.contains("<Key>env</Key>"));
        assert!(xml.contains("<Value>prod</Value>"));
    }
}
