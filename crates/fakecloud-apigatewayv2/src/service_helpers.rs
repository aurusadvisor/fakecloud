use super::*;

/// Pick the action name for the collection-level endpoints —
/// /v2/apis/{id}/{collection} — where `col` is one of routes,
/// integrations, stages, deployments, authorizers and `method`
/// is either POST (create) or GET (list).
pub(crate) fn resolve_collection_action(method: &Method, collection: &str) -> Option<&'static str> {
    match (method.clone(), collection) {
        (Method::POST, "routes") => Some("CreateRoute"),
        (Method::GET, "routes") => Some("GetRoutes"),
        (Method::POST, "integrations") => Some("CreateIntegration"),
        (Method::GET, "integrations") => Some("GetIntegrations"),
        (Method::POST, "stages") => Some("CreateStage"),
        (Method::GET, "stages") => Some("GetStages"),
        (Method::POST, "deployments") => Some("CreateDeployment"),
        (Method::GET, "deployments") => Some("GetDeployments"),
        (Method::POST, "authorizers") => Some("CreateAuthorizer"),
        (Method::GET, "authorizers") => Some("GetAuthorizers"),
        (Method::POST, "models") => Some("CreateModel"),
        (Method::GET, "models") => Some("GetModels"),
        (Method::DELETE, "cors") => Some("DeleteCorsConfiguration"),
        _ => None,
    }
}

/// Pick the action name for the resource-level endpoints —
/// /v2/apis/{id}/{collection}/{resource-id} — where `col` is one of
/// routes, integrations, stages, deployments, authorizers and
/// `method` is GET (describe), PATCH (update), or DELETE.
pub(crate) fn resolve_resource_action(method: &Method, collection: &str) -> Option<&'static str> {
    match (method.clone(), collection) {
        (Method::GET, "routes") => Some("GetRoute"),
        (Method::PATCH, "routes") => Some("UpdateRoute"),
        (Method::DELETE, "routes") => Some("DeleteRoute"),
        (Method::GET, "integrations") => Some("GetIntegration"),
        (Method::PATCH, "integrations") => Some("UpdateIntegration"),
        (Method::DELETE, "integrations") => Some("DeleteIntegration"),
        (Method::GET, "stages") => Some("GetStage"),
        (Method::PATCH, "stages") => Some("UpdateStage"),
        (Method::DELETE, "stages") => Some("DeleteStage"),
        (Method::GET, "deployments") => Some("GetDeployment"),
        (Method::PATCH, "deployments") => Some("UpdateDeployment"),
        (Method::DELETE, "deployments") => Some("DeleteDeployment"),
        (Method::GET, "authorizers") => Some("GetAuthorizer"),
        (Method::PATCH, "authorizers") => Some("UpdateAuthorizer"),
        (Method::DELETE, "authorizers") => Some("DeleteAuthorizer"),
        (Method::POST, "authorizers") => Some("ResetAuthorizersCache"),
        (Method::GET, "models") => Some("GetModel"),
        (Method::PATCH, "models") => Some("UpdateModel"),
        (Method::DELETE, "models") => Some("DeleteModel"),
        (Method::GET, "exports") => Some("ExportApi"),
        _ => None,
    }
}

pub(crate) fn generate_id(prefix: &str) -> String {
    let uuid = uuid::Uuid::new_v4().to_string().replace('-', "");
    format!("{}{}", prefix, &uuid[..10])
}
