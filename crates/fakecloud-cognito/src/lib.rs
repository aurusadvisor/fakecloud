pub mod jwt;
pub(crate) mod service;
pub(crate) mod state;
pub mod triggers;
pub mod user_status;

pub use service::{
    ensure_pool_signing_key, handle_oauth2_revoke, handle_oauth2_token, handle_oauth2_userinfo,
    oidc_discovery_document, pool_jwks_document, CognitoService, OAuthRevokeError, OAuthTokenError,
    OAuthTokenResponse, OAuthUserInfoError,
};
pub use state::{
    default_schema_attributes, AccountRecoverySetting, AdminCreateUserConfig, CognitoSnapshot,
    CognitoState, CustomDomainConfig, EmailConfiguration, PasswordPolicy, PoolPolicies,
    RecoveryOption, SchemaAttribute, SharedCognitoState, SignInPolicy, SmsConfiguration, UserPool,
    UserPoolClient, UserPoolDomain, COGNITO_SNAPSHOT_SCHEMA_VERSION,
};

/// `CognitoJwtVerifier` impl backed by the in-process Cognito state.
/// Wired by fakecloud-server so cross-service consumers (API Gateway v1
/// `COGNITO_USER_POOLS` authorizer) can verify pool-issued JWTs without
/// taking a hard dep on `fakecloud-cognito`.
pub struct StateBackedJwtVerifier {
    state: SharedCognitoState,
}

impl StateBackedJwtVerifier {
    pub fn new(state: SharedCognitoState) -> Self {
        Self { state }
    }
}

impl fakecloud_core::delivery::CognitoJwtVerifier for StateBackedJwtVerifier {
    fn verify_token(
        &self,
        account_id: &str,
        user_pool_arn: &str,
        token: &str,
    ) -> Result<serde_json::Value, String> {
        // Resolve the pool by ARN inside the requested account. ARN form:
        // `arn:aws:cognito-idp:<region>:<account>:userpool/<pool-id>`.
        let pool_id = user_pool_arn
            .rsplit_once("userpool/")
            .map(|(_, id)| id.to_string())
            .ok_or_else(|| format!("invalid Cognito user pool ARN: {user_pool_arn}"))?;
        let accounts = self.state.read();
        let state = accounts
            .get(account_id)
            .ok_or_else(|| format!("no Cognito state for account {account_id}"))?;
        let pool = state
            .user_pools
            .get(&pool_id)
            .ok_or_else(|| format!("user pool {pool_id} not found"))?;
        let pem = pool
            .signing_key_pem
            .as_deref()
            .ok_or_else(|| format!("user pool {pool_id} has no signing key"))?;
        let (_header, payload) = jwt::verify_rs256(token, pem)?;

        // Validate exp and iss now that the signature has been confirmed.
        // Cognito-issued tokens always carry both.
        if let Some(exp) = payload.get("exp").and_then(|v| v.as_i64()) {
            let now = chrono::Utc::now().timestamp();
            if now >= exp {
                return Err("token expired".to_string());
            }
        }
        if let Some(iss) = payload.get("iss").and_then(|v| v.as_str()) {
            // `iss` matches `https://cognito-idp.<region>.amazonaws.com/<pool-id>`
            // exactly for pools that haven't customized their issuer.
            if !iss.ends_with(&format!("/{pool_id}")) {
                return Err(format!("token issuer {iss} does not match pool {pool_id}"));
            }
        }
        Ok(payload)
    }
}
