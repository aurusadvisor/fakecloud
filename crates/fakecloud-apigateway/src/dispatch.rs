//! REST-URL -> action resolver for API Gateway v1.
//!
//! AWS's API Gateway v1 control plane uses a REST-style URL surface
//! (`GET /restapis/{id}/resources`, `POST /restapis/{id}/deployments`,
//! …) instead of action-based dispatch. This module maps an incoming
//! `(method, path_segments)` tuple to the corresponding Smithy action
//! name plus extracted path parameters.
//!
//! The dispatcher is intentionally exhaustive — every operation in the
//! v1 Smithy model is covered. Operations that aren't routed here
//! return `None`, which causes the service to respond with
//! `ActionNotImplemented`.
//!
//! Path parameters are returned in a `HashMap<String, String>` keyed
//! by the segment name AWS uses (`restApiId`, `resourceId`,
//! `apiKeyId`, etc.) so handlers don't have to re-parse the URL.

use http::Method;
use std::collections::HashMap;

/// Returns true when the request's `mode` query parameter equals `import`.
/// `POST /restapis?mode=import` is the AWS REST shape for `ImportRestApi`,
/// distinguished from `CreateRestApi` only by this query parameter.
fn is_import_mode(query_params: &HashMap<String, String>) -> bool {
    query_params.get("mode").map(String::as_str) == Some("import")
}

#[derive(Debug, Clone)]
pub struct ResolvedAction {
    pub action: &'static str,
    pub params: HashMap<String, String>,
}

impl ResolvedAction {
    fn new(action: &'static str) -> Self {
        Self {
            action,
            params: HashMap::new(),
        }
    }

    fn with(mut self, key: &str, value: &str) -> Self {
        self.params.insert(key.to_string(), value.to_string());
        self
    }
}

/// Resolve `(method, path)` to an action and path-parameter map. The
/// segments slice should already exclude any leading `/`; e.g.
/// `/restapis/abc/resources` -> `["restapis", "abc", "resources"]`.
/// Query parameters disambiguate routes that share a path+method
/// (`POST /restapis` vs `POST /restapis?mode=import`).
pub fn resolve(
    method: &Method,
    segs: &[String],
    query_params: &HashMap<String, String>,
) -> Option<ResolvedAction> {
    let s: Vec<&str> = segs.iter().map(|s| s.as_str()).collect();
    match (method.clone(), s.as_slice()) {
        // Account
        (Method::GET, ["account"]) => Some(ResolvedAction::new("GetAccount")),
        (Method::PATCH, ["account"]) => Some(ResolvedAction::new("UpdateAccount")),

        // REST APIs
        (Method::POST, ["restapis"]) if is_import_mode(query_params) => {
            Some(ResolvedAction::new("ImportRestApi"))
        }
        (Method::POST, ["restapis"]) => Some(ResolvedAction::new("CreateRestApi")),
        (Method::GET, ["restapis"]) => Some(ResolvedAction::new("GetRestApis")),
        (Method::GET, ["restapis", id]) => {
            Some(ResolvedAction::new("GetRestApi").with("restApiId", id))
        }
        (Method::DELETE, ["restapis", id]) => {
            Some(ResolvedAction::new("DeleteRestApi").with("restApiId", id))
        }
        (Method::PATCH, ["restapis", id]) => {
            Some(ResolvedAction::new("UpdateRestApi").with("restApiId", id))
        }
        (Method::PUT, ["restapis", id]) => {
            // PUT on /restapis/{id} is PutRestApi — used for OpenAPI
            // overwrite/merge. Distinguish from the `?mode=import`
            // route below by checking for a body; both AWS and we route
            // here.
            Some(ResolvedAction::new("PutRestApi").with("restApiId", id))
        }
        // Resources
        (Method::GET, ["restapis", api, "resources"]) => {
            Some(ResolvedAction::new("GetResources").with("restApiId", api))
        }
        (Method::GET, ["restapis", api, "resources", id]) => Some(
            ResolvedAction::new("GetResource")
                .with("restApiId", api)
                .with("resourceId", id),
        ),
        (Method::POST, ["restapis", api, "resources", parent]) => Some(
            ResolvedAction::new("CreateResource")
                .with("restApiId", api)
                .with("parentId", parent),
        ),
        (Method::DELETE, ["restapis", api, "resources", id]) => Some(
            ResolvedAction::new("DeleteResource")
                .with("restApiId", api)
                .with("resourceId", id),
        ),
        (Method::PATCH, ["restapis", api, "resources", id]) => Some(
            ResolvedAction::new("UpdateResource")
                .with("restApiId", api)
                .with("resourceId", id),
        ),

        // Methods
        (Method::PUT, ["restapis", api, "resources", res, "methods", m]) => Some(
            ResolvedAction::new("PutMethod")
                .with("restApiId", api)
                .with("resourceId", res)
                .with("httpMethod", m),
        ),
        (Method::GET, ["restapis", api, "resources", res, "methods", m]) => Some(
            ResolvedAction::new("GetMethod")
                .with("restApiId", api)
                .with("resourceId", res)
                .with("httpMethod", m),
        ),
        (Method::DELETE, ["restapis", api, "resources", res, "methods", m]) => Some(
            ResolvedAction::new("DeleteMethod")
                .with("restApiId", api)
                .with("resourceId", res)
                .with("httpMethod", m),
        ),
        (Method::PATCH, ["restapis", api, "resources", res, "methods", m]) => Some(
            ResolvedAction::new("UpdateMethod")
                .with("restApiId", api)
                .with("resourceId", res)
                .with("httpMethod", m),
        ),

        // Method responses
        (Method::PUT, ["restapis", api, "resources", res, "methods", m, "responses", code]) => {
            Some(
                ResolvedAction::new("PutMethodResponse")
                    .with("restApiId", api)
                    .with("resourceId", res)
                    .with("httpMethod", m)
                    .with("statusCode", code),
            )
        }
        (Method::GET, ["restapis", api, "resources", res, "methods", m, "responses", code]) => {
            Some(
                ResolvedAction::new("GetMethodResponse")
                    .with("restApiId", api)
                    .with("resourceId", res)
                    .with("httpMethod", m)
                    .with("statusCode", code),
            )
        }
        (Method::DELETE, ["restapis", api, "resources", res, "methods", m, "responses", code]) => {
            Some(
                ResolvedAction::new("DeleteMethodResponse")
                    .with("restApiId", api)
                    .with("resourceId", res)
                    .with("httpMethod", m)
                    .with("statusCode", code),
            )
        }
        (Method::PATCH, ["restapis", api, "resources", res, "methods", m, "responses", code]) => {
            Some(
                ResolvedAction::new("UpdateMethodResponse")
                    .with("restApiId", api)
                    .with("resourceId", res)
                    .with("httpMethod", m)
                    .with("statusCode", code),
            )
        }

        // Integrations
        (Method::PUT, ["restapis", api, "resources", res, "methods", m, "integration"]) => Some(
            ResolvedAction::new("PutIntegration")
                .with("restApiId", api)
                .with("resourceId", res)
                .with("httpMethod", m),
        ),
        (Method::GET, ["restapis", api, "resources", res, "methods", m, "integration"]) => Some(
            ResolvedAction::new("GetIntegration")
                .with("restApiId", api)
                .with("resourceId", res)
                .with("httpMethod", m),
        ),
        (Method::DELETE, ["restapis", api, "resources", res, "methods", m, "integration"]) => Some(
            ResolvedAction::new("DeleteIntegration")
                .with("restApiId", api)
                .with("resourceId", res)
                .with("httpMethod", m),
        ),
        (Method::PATCH, ["restapis", api, "resources", res, "methods", m, "integration"]) => Some(
            ResolvedAction::new("UpdateIntegration")
                .with("restApiId", api)
                .with("resourceId", res)
                .with("httpMethod", m),
        ),

        // Integration responses
        (
            Method::PUT,
            ["restapis", api, "resources", res, "methods", m, "integration", "responses", code],
        ) => Some(
            ResolvedAction::new("PutIntegrationResponse")
                .with("restApiId", api)
                .with("resourceId", res)
                .with("httpMethod", m)
                .with("statusCode", code),
        ),
        (
            Method::GET,
            ["restapis", api, "resources", res, "methods", m, "integration", "responses", code],
        ) => Some(
            ResolvedAction::new("GetIntegrationResponse")
                .with("restApiId", api)
                .with("resourceId", res)
                .with("httpMethod", m)
                .with("statusCode", code),
        ),
        (
            Method::DELETE,
            ["restapis", api, "resources", res, "methods", m, "integration", "responses", code],
        ) => Some(
            ResolvedAction::new("DeleteIntegrationResponse")
                .with("restApiId", api)
                .with("resourceId", res)
                .with("httpMethod", m)
                .with("statusCode", code),
        ),
        (
            Method::PATCH,
            ["restapis", api, "resources", res, "methods", m, "integration", "responses", code],
        ) => Some(
            ResolvedAction::new("UpdateIntegrationResponse")
                .with("restApiId", api)
                .with("resourceId", res)
                .with("httpMethod", m)
                .with("statusCode", code),
        ),

        // Test invocations
        (Method::POST, ["restapis", api, "resources", res, "methods", m]) => Some(
            ResolvedAction::new("TestInvokeMethod")
                .with("restApiId", api)
                .with("resourceId", res)
                .with("httpMethod", m),
        ),
        (Method::POST, ["restapis", api, "authorizers", auth]) => Some(
            ResolvedAction::new("TestInvokeAuthorizer")
                .with("restApiId", api)
                .with("authorizerId", auth),
        ),

        // Deployments
        (Method::POST, ["restapis", api, "deployments"]) => {
            Some(ResolvedAction::new("CreateDeployment").with("restApiId", api))
        }
        (Method::GET, ["restapis", api, "deployments"]) => {
            Some(ResolvedAction::new("GetDeployments").with("restApiId", api))
        }
        (Method::GET, ["restapis", api, "deployments", id]) => Some(
            ResolvedAction::new("GetDeployment")
                .with("restApiId", api)
                .with("deploymentId", id),
        ),
        (Method::DELETE, ["restapis", api, "deployments", id]) => Some(
            ResolvedAction::new("DeleteDeployment")
                .with("restApiId", api)
                .with("deploymentId", id),
        ),
        (Method::PATCH, ["restapis", api, "deployments", id]) => Some(
            ResolvedAction::new("UpdateDeployment")
                .with("restApiId", api)
                .with("deploymentId", id),
        ),

        // Stages
        (Method::POST, ["restapis", api, "stages"]) => {
            Some(ResolvedAction::new("CreateStage").with("restApiId", api))
        }
        (Method::GET, ["restapis", api, "stages"]) => {
            Some(ResolvedAction::new("GetStages").with("restApiId", api))
        }
        (Method::GET, ["restapis", api, "stages", name]) => Some(
            ResolvedAction::new("GetStage")
                .with("restApiId", api)
                .with("stageName", name),
        ),
        (Method::DELETE, ["restapis", api, "stages", name]) => Some(
            ResolvedAction::new("DeleteStage")
                .with("restApiId", api)
                .with("stageName", name),
        ),
        (Method::PATCH, ["restapis", api, "stages", name]) => Some(
            ResolvedAction::new("UpdateStage")
                .with("restApiId", api)
                .with("stageName", name),
        ),
        (Method::DELETE, ["restapis", api, "stages", name, "cache", "data"]) => Some(
            ResolvedAction::new("FlushStageCache")
                .with("restApiId", api)
                .with("stageName", name),
        ),
        (Method::DELETE, ["restapis", api, "stages", name, "cache", "authorizers"]) => Some(
            ResolvedAction::new("FlushStageAuthorizersCache")
                .with("restApiId", api)
                .with("stageName", name),
        ),

        // Models
        (Method::POST, ["restapis", api, "models"]) => {
            Some(ResolvedAction::new("CreateModel").with("restApiId", api))
        }
        (Method::GET, ["restapis", api, "models"]) => {
            Some(ResolvedAction::new("GetModels").with("restApiId", api))
        }
        (Method::GET, ["restapis", api, "models", name]) => Some(
            ResolvedAction::new("GetModel")
                .with("restApiId", api)
                .with("modelName", name),
        ),
        (Method::GET, ["restapis", api, "models", name, "default_template"]) => Some(
            ResolvedAction::new("GetModelTemplate")
                .with("restApiId", api)
                .with("modelName", name),
        ),
        (Method::DELETE, ["restapis", api, "models", name]) => Some(
            ResolvedAction::new("DeleteModel")
                .with("restApiId", api)
                .with("modelName", name),
        ),
        (Method::PATCH, ["restapis", api, "models", name]) => Some(
            ResolvedAction::new("UpdateModel")
                .with("restApiId", api)
                .with("modelName", name),
        ),

        // Request validators
        (Method::POST, ["restapis", api, "requestvalidators"]) => {
            Some(ResolvedAction::new("CreateRequestValidator").with("restApiId", api))
        }
        (Method::GET, ["restapis", api, "requestvalidators"]) => {
            Some(ResolvedAction::new("GetRequestValidators").with("restApiId", api))
        }
        (Method::GET, ["restapis", api, "requestvalidators", id]) => Some(
            ResolvedAction::new("GetRequestValidator")
                .with("restApiId", api)
                .with("requestValidatorId", id),
        ),
        (Method::DELETE, ["restapis", api, "requestvalidators", id]) => Some(
            ResolvedAction::new("DeleteRequestValidator")
                .with("restApiId", api)
                .with("requestValidatorId", id),
        ),
        (Method::PATCH, ["restapis", api, "requestvalidators", id]) => Some(
            ResolvedAction::new("UpdateRequestValidator")
                .with("restApiId", api)
                .with("requestValidatorId", id),
        ),

        // Authorizers
        (Method::POST, ["restapis", api, "authorizers"]) => {
            Some(ResolvedAction::new("CreateAuthorizer").with("restApiId", api))
        }
        (Method::GET, ["restapis", api, "authorizers"]) => {
            Some(ResolvedAction::new("GetAuthorizers").with("restApiId", api))
        }
        (Method::GET, ["restapis", api, "authorizers", id]) => Some(
            ResolvedAction::new("GetAuthorizer")
                .with("restApiId", api)
                .with("authorizerId", id),
        ),
        (Method::DELETE, ["restapis", api, "authorizers", id]) => Some(
            ResolvedAction::new("DeleteAuthorizer")
                .with("restApiId", api)
                .with("authorizerId", id),
        ),
        (Method::PATCH, ["restapis", api, "authorizers", id]) => Some(
            ResolvedAction::new("UpdateAuthorizer")
                .with("restApiId", api)
                .with("authorizerId", id),
        ),

        // API Keys (ImportApiKeys is the same path with `?mode=import`)
        (Method::POST, ["apikeys"]) if is_import_mode(query_params) => {
            Some(ResolvedAction::new("ImportApiKeys"))
        }
        (Method::POST, ["apikeys"]) => Some(ResolvedAction::new("CreateApiKey")),
        (Method::GET, ["apikeys"]) => Some(ResolvedAction::new("GetApiKeys")),
        (Method::GET, ["apikeys", id]) => {
            Some(ResolvedAction::new("GetApiKey").with("apiKeyId", id))
        }
        (Method::DELETE, ["apikeys", id]) => {
            Some(ResolvedAction::new("DeleteApiKey").with("apiKeyId", id))
        }
        (Method::PATCH, ["apikeys", id]) => {
            Some(ResolvedAction::new("UpdateApiKey").with("apiKeyId", id))
        }

        // Usage plans + keys
        (Method::POST, ["usageplans"]) => Some(ResolvedAction::new("CreateUsagePlan")),
        (Method::GET, ["usageplans"]) => Some(ResolvedAction::new("GetUsagePlans")),
        (Method::GET, ["usageplans", id]) => {
            Some(ResolvedAction::new("GetUsagePlan").with("usagePlanId", id))
        }
        (Method::DELETE, ["usageplans", id]) => {
            Some(ResolvedAction::new("DeleteUsagePlan").with("usagePlanId", id))
        }
        (Method::PATCH, ["usageplans", id]) => {
            Some(ResolvedAction::new("UpdateUsagePlan").with("usagePlanId", id))
        }
        (Method::POST, ["usageplans", id, "keys"]) => {
            Some(ResolvedAction::new("CreateUsagePlanKey").with("usagePlanId", id))
        }
        (Method::GET, ["usageplans", id, "keys"]) => {
            Some(ResolvedAction::new("GetUsagePlanKeys").with("usagePlanId", id))
        }
        (Method::GET, ["usageplans", id, "keys", k]) => Some(
            ResolvedAction::new("GetUsagePlanKey")
                .with("usagePlanId", id)
                .with("keyId", k),
        ),
        (Method::DELETE, ["usageplans", id, "keys", k]) => Some(
            ResolvedAction::new("DeleteUsagePlanKey")
                .with("usagePlanId", id)
                .with("keyId", k),
        ),
        (Method::GET, ["usageplans", id, "usage"]) => {
            Some(ResolvedAction::new("GetUsage").with("usagePlanId", id))
        }
        (Method::PATCH, ["usageplans", id, "usage"]) => {
            Some(ResolvedAction::new("UpdateUsage").with("usagePlanId", id))
        }

        // VPC links
        (Method::POST, ["vpclinks"]) => Some(ResolvedAction::new("CreateVpcLink")),
        (Method::GET, ["vpclinks"]) => Some(ResolvedAction::new("GetVpcLinks")),
        (Method::GET, ["vpclinks", id]) => {
            Some(ResolvedAction::new("GetVpcLink").with("vpcLinkId", id))
        }
        (Method::DELETE, ["vpclinks", id]) => {
            Some(ResolvedAction::new("DeleteVpcLink").with("vpcLinkId", id))
        }
        (Method::PATCH, ["vpclinks", id]) => {
            Some(ResolvedAction::new("UpdateVpcLink").with("vpcLinkId", id))
        }

        // Domain name access associations (cross-account access for
        // private custom domain names). Stored opaquely; the AWS shape
        // only requires round-tripping the JSON envelope.
        (Method::POST, ["domainnameaccessassociations"]) => {
            Some(ResolvedAction::new("CreateDomainNameAccessAssociation"))
        }
        (Method::GET, ["domainnameaccessassociations"]) => {
            Some(ResolvedAction::new("GetDomainNameAccessAssociations"))
        }
        (Method::DELETE, ["domainnameaccessassociations", first, rest @ ..]) => {
            let mut arn = (*first).to_string();
            for seg in rest {
                arn.push('/');
                arn.push_str(seg);
            }
            Some(
                ResolvedAction::new("DeleteDomainNameAccessAssociation")
                    .with("domainNameAccessAssociationArn", &arn),
            )
        }
        (Method::POST, ["rejectdomainnameaccessassociations"]) => {
            let mut a = ResolvedAction::new("RejectDomainNameAccessAssociation");
            if let Some(arn) = query_params.get("domainNameAccessAssociationArn") {
                a = a.with("domainNameAccessAssociationArn", arn);
            }
            if let Some(name) = query_params.get("domainName") {
                a = a.with("domainName", name);
            }
            Some(a)
        }

        // ImportDocumentationParts (PUT on the same path that POST hits
        // for CreateDocumentationPart).
        (Method::PUT, ["restapis", api, "documentation", "parts"]) => {
            Some(ResolvedAction::new("ImportDocumentationParts").with("restApiId", api))
        }

        // Domain names + base path mappings
        (Method::POST, ["domainnames"]) => Some(ResolvedAction::new("CreateDomainName")),
        (Method::GET, ["domainnames"]) => Some(ResolvedAction::new("GetDomainNames")),
        (Method::GET, ["domainnames", d]) => {
            Some(ResolvedAction::new("GetDomainName").with("domainName", d))
        }
        (Method::DELETE, ["domainnames", d]) => {
            Some(ResolvedAction::new("DeleteDomainName").with("domainName", d))
        }
        (Method::PATCH, ["domainnames", d]) => {
            Some(ResolvedAction::new("UpdateDomainName").with("domainName", d))
        }
        (Method::POST, ["domainnames", d, "basepathmappings"]) => {
            Some(ResolvedAction::new("CreateBasePathMapping").with("domainName", d))
        }
        (Method::GET, ["domainnames", d, "basepathmappings"]) => {
            Some(ResolvedAction::new("GetBasePathMappings").with("domainName", d))
        }
        (Method::GET, ["domainnames", d, "basepathmappings", bp]) => Some(
            ResolvedAction::new("GetBasePathMapping")
                .with("domainName", d)
                .with("basePath", bp),
        ),
        (Method::DELETE, ["domainnames", d, "basepathmappings", bp]) => Some(
            ResolvedAction::new("DeleteBasePathMapping")
                .with("domainName", d)
                .with("basePath", bp),
        ),
        (Method::PATCH, ["domainnames", d, "basepathmappings", bp]) => Some(
            ResolvedAction::new("UpdateBasePathMapping")
                .with("domainName", d)
                .with("basePath", bp),
        ),

        // Client certificates
        (Method::POST, ["clientcertificates"]) => {
            Some(ResolvedAction::new("GenerateClientCertificate"))
        }
        (Method::GET, ["clientcertificates"]) => Some(ResolvedAction::new("GetClientCertificates")),
        (Method::GET, ["clientcertificates", id]) => {
            Some(ResolvedAction::new("GetClientCertificate").with("clientCertificateId", id))
        }
        (Method::DELETE, ["clientcertificates", id]) => {
            Some(ResolvedAction::new("DeleteClientCertificate").with("clientCertificateId", id))
        }
        (Method::PATCH, ["clientcertificates", id]) => {
            Some(ResolvedAction::new("UpdateClientCertificate").with("clientCertificateId", id))
        }

        // Documentation parts + versions
        (Method::POST, ["restapis", api, "documentation", "parts"]) => {
            Some(ResolvedAction::new("CreateDocumentationPart").with("restApiId", api))
        }
        (Method::GET, ["restapis", api, "documentation", "parts"]) => {
            Some(ResolvedAction::new("GetDocumentationParts").with("restApiId", api))
        }
        (Method::GET, ["restapis", api, "documentation", "parts", id]) => Some(
            ResolvedAction::new("GetDocumentationPart")
                .with("restApiId", api)
                .with("documentationPartId", id),
        ),
        (Method::DELETE, ["restapis", api, "documentation", "parts", id]) => Some(
            ResolvedAction::new("DeleteDocumentationPart")
                .with("restApiId", api)
                .with("documentationPartId", id),
        ),
        (Method::PATCH, ["restapis", api, "documentation", "parts", id]) => Some(
            ResolvedAction::new("UpdateDocumentationPart")
                .with("restApiId", api)
                .with("documentationPartId", id),
        ),
        (Method::POST, ["restapis", api, "documentation", "versions"]) => {
            Some(ResolvedAction::new("CreateDocumentationVersion").with("restApiId", api))
        }
        (Method::GET, ["restapis", api, "documentation", "versions"]) => {
            Some(ResolvedAction::new("GetDocumentationVersions").with("restApiId", api))
        }
        (Method::GET, ["restapis", api, "documentation", "versions", v]) => Some(
            ResolvedAction::new("GetDocumentationVersion")
                .with("restApiId", api)
                .with("documentationVersion", v),
        ),
        (Method::DELETE, ["restapis", api, "documentation", "versions", v]) => Some(
            ResolvedAction::new("DeleteDocumentationVersion")
                .with("restApiId", api)
                .with("documentationVersion", v),
        ),
        (Method::PATCH, ["restapis", api, "documentation", "versions", v]) => Some(
            ResolvedAction::new("UpdateDocumentationVersion")
                .with("restApiId", api)
                .with("documentationVersion", v),
        ),

        // Gateway responses
        (Method::PUT, ["restapis", api, "gatewayresponses", t]) => Some(
            ResolvedAction::new("PutGatewayResponse")
                .with("restApiId", api)
                .with("responseType", t),
        ),
        (Method::GET, ["restapis", api, "gatewayresponses"]) => {
            Some(ResolvedAction::new("GetGatewayResponses").with("restApiId", api))
        }
        (Method::GET, ["restapis", api, "gatewayresponses", t]) => Some(
            ResolvedAction::new("GetGatewayResponse")
                .with("restApiId", api)
                .with("responseType", t),
        ),
        (Method::DELETE, ["restapis", api, "gatewayresponses", t]) => Some(
            ResolvedAction::new("DeleteGatewayResponse")
                .with("restApiId", api)
                .with("responseType", t),
        ),
        (Method::PATCH, ["restapis", api, "gatewayresponses", t]) => Some(
            ResolvedAction::new("UpdateGatewayResponse")
                .with("restApiId", api)
                .with("responseType", t),
        ),

        // Export, import, SDK generation
        (Method::GET, ["restapis", api, "stages", stage, "exports", t]) => Some(
            ResolvedAction::new("GetExport")
                .with("restApiId", api)
                .with("stageName", stage)
                .with("exportType", t),
        ),
        (Method::GET, ["restapis", api, "stages", stage, "sdks", t]) => Some(
            ResolvedAction::new("GetSdk")
                .with("restApiId", api)
                .with("stageName", stage)
                .with("sdkType", t),
        ),
        (Method::GET, ["sdktypes"]) => Some(ResolvedAction::new("GetSdkTypes")),
        (Method::GET, ["sdktypes", id]) => Some(ResolvedAction::new("GetSdkType").with("id", id)),

        // Tags
        (Method::PUT, ["tags", arn @ ..]) => {
            Some(ResolvedAction::new("TagResource").with("resourceArn", &arn.join("/")))
        }
        (Method::DELETE, ["tags", arn @ ..]) => {
            Some(ResolvedAction::new("UntagResource").with("resourceArn", &arn.join("/")))
        }
        (Method::GET, ["tags", arn @ ..]) => {
            Some(ResolvedAction::new("GetTags").with("resourceArn", &arn.join("/")))
        }

        _ => None,
    }
}
