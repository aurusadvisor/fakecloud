//! Combined v1+v2 facade.
//!
//! Real AWS uses one SigV4 service identifier (`apigateway`) for both
//! API Gateway v1 (REST APIs, `/restapis/...`) and API Gateway v2
//! (HTTP APIs, `/v2/...`), distinguished only by URL. fakecloud's
//! service registry is keyed by SigV4 service name, so we wrap both
//! handlers behind a single registered `"apigateway"` entry that
//! routes by URL prefix.

use async_trait::async_trait;
use std::collections::HashSet;
use std::sync::Arc;

use fakecloud_core::service::{AwsRequest, AwsResponse, AwsService, AwsServiceError};

use crate::ApiGatewayService;

const V1_CONTROL_PREFIXES: &[&str] = &[
    "restapis",
    "apikeys",
    "usageplans",
    "vpclinks",
    "domainnames",
    "domainnameaccessassociations",
    "rejectdomainnameaccessassociations",
    "clientcertificates",
    "sdktypes",
    "tags",
    "account",
];

pub struct ApiGatewayFacade {
    v1: Arc<ApiGatewayService>,
    v2: Arc<dyn AwsService>,
    actions: Vec<&'static str>,
}

impl ApiGatewayFacade {
    pub fn new(v1: Arc<ApiGatewayService>, v2: Arc<dyn AwsService>) -> Self {
        // Combine the two services' supported_actions slices into one
        // de-duplicated list and leak it — the conformance audit
        // already inspects the v1 and v2 crate sources separately, so
        // this slice is only used by runtime introspection.
        let mut set: HashSet<&str> = HashSet::new();
        for &a in v1.supported_actions() {
            set.insert(a);
        }
        for &a in v2.supported_actions() {
            set.insert(a);
        }
        let mut sorted: Vec<&str> = set.into_iter().collect();
        sorted.sort();
        let leaked: Vec<&'static str> = sorted
            .into_iter()
            .map(|s| Box::leak(s.to_string().into_boxed_str()) as &'static str)
            .collect();
        Self {
            v1,
            v2,
            actions: leaked,
        }
    }

    fn route_v1(req: &AwsRequest) -> bool {
        req.path_segments
            .first()
            .map(|s| V1_CONTROL_PREFIXES.contains(&s.as_str()))
            .unwrap_or(false)
    }

    fn route_v2_control(req: &AwsRequest) -> bool {
        req.path_segments
            .first()
            .map(|s| s == "v2")
            .unwrap_or(false)
    }

    /// Returns true when the data-plane request targets an API ID that
    /// exists in v1 state. AWS keys the execute-api host on the API ID
    /// (`{api-id}.execute-api.<region>.amazonaws.com`); fakecloud
    /// surfaces it via the `Host` header. Stage-name lookups would
    /// misroute traffic when v1 and v2 share a stage name.
    fn data_plane_owned_by_v1(&self, req: &AwsRequest) -> bool {
        let Some(host) = req.headers.get("host").and_then(|v| v.to_str().ok()) else {
            return false;
        };
        let Some(api_id) = host.split('.').next() else {
            return false;
        };
        if api_id.is_empty() {
            return false;
        }
        let accounts = self.v1.state_handle().read();
        let Some(state) = accounts.get(&req.account_id) else {
            return false;
        };
        state.apis.contains_key(api_id)
    }
}

#[async_trait]
impl AwsService for ApiGatewayFacade {
    fn service_name(&self) -> &str {
        "apigateway"
    }

    fn supported_actions(&self) -> &[&str] {
        &self.actions
    }

    async fn handle(&self, req: AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        if Self::route_v2_control(&req) {
            return self.v2.handle(req).await;
        }
        if Self::route_v1(&req) {
            return self.v1.handle(req).await;
        }
        if self.data_plane_owned_by_v1(&req) {
            return self.v1.handle(req).await;
        }
        // Default fallback for unsigned execute calls — v2 was the
        // original handler and remains the default until v1 has
        // matching state.
        self.v2.handle(req).await
    }
}
