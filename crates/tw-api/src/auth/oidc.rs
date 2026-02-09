//! OpenID Connect authentication flow.
//!
//! The implementation intentionally validates core token claims and performs
//! secure state/nonce checks. Signature verification can be enabled later with
//! JWKS verification, but this flow already fail-closes on issuer/audience/nonce
//! mismatch and expired tokens.

use crate::auth::{clear_session, set_session_data};
use crate::error::ApiError;
use crate::state::AppState;
use axum::extract::{Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::Utc;
use rand::rngs::OsRng;
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use subtle::ConstantTimeEq;
use tower_sessions::Session;
use tracing::{info, warn};
use tw_core::auth::SessionData;
use tw_core::db::create_user_repository;
use tw_core::{ClaimsMapping, OidcConfig};
use uuid::Uuid;

use super::provisioning::{SsoClaims, UserProvisioner};

const OIDC_STATE_KEY: &str = "oidc_state";
const OIDC_NONCE_KEY: &str = "oidc_nonce";
const OIDC_CODE_VERIFIER_KEY: &str = "oidc_code_verifier";
const OIDC_PROVIDER_KEY: &str = "oidc_provider";
const OIDC_REDIRECT_KEY: &str = "oidc_redirect";
const OIDC_REFRESH_TOKEN_KEY: &str = "oidc_refresh_token";
const OIDC_ID_TOKEN_KEY: &str = "oidc_id_token";
const OIDC_END_SESSION_KEY: &str = "oidc_end_session_endpoint";

/// OIDC route set mounted at `/auth/oidc`.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/login", get(login))
        .route("/callback", get(callback))
        .route("/logout", get(logout))
        .route("/refresh", post(refresh))
}

#[derive(Debug, Deserialize)]
struct OidcLoginQuery {
    provider: Option<String>,
    redirect: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OidcCallbackQuery {
    code: String,
    state: String,
}

#[derive(Debug, Serialize)]
struct OidcRefreshResponse {
    refreshed: bool,
    expires_in: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct OidcDiscoveryDocument {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: Option<String>,
    end_session_endpoint: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OidcTokenResponse {
    access_token: String,
    token_type: Option<String>,
    id_token: Option<String>,
    refresh_token: Option<String>,
    expires_in: Option<u64>,
}

#[derive(Debug)]
struct NormalizedOidcConfig {
    provider_name: String,
    base: OidcConfig,
    discovery: OidcDiscoveryDocument,
}

async fn login(
    session: Session,
    Query(query): Query<OidcLoginQuery>,
) -> Result<Response, ApiError> {
    let provider_name = query.provider.unwrap_or_else(|| "default".to_string());
    let config = load_oidc_config(&provider_name)?;
    let discovery = discover(&config).await?;
    let normalized = NormalizedOidcConfig {
        provider_name,
        base: config,
        discovery,
    };

    let state = random_token(48);
    let nonce = random_token(48);
    let code_verifier = random_token(64);
    let code_challenge = pkce_challenge(&code_verifier);

    session
        .insert(OIDC_STATE_KEY, state.clone())
        .await
        .map_err(|e| ApiError::Internal(format!("failed to store oidc state: {e}")))?;
    session
        .insert(OIDC_NONCE_KEY, nonce.clone())
        .await
        .map_err(|e| ApiError::Internal(format!("failed to store oidc nonce: {e}")))?;
    session
        .insert(OIDC_CODE_VERIFIER_KEY, code_verifier)
        .await
        .map_err(|e| ApiError::Internal(format!("failed to store oidc verifier: {e}")))?;
    session
        .insert(OIDC_PROVIDER_KEY, normalized.provider_name.clone())
        .await
        .map_err(|e| ApiError::Internal(format!("failed to store oidc provider: {e}")))?;

    if let Some(redirect) = query.redirect {
        if is_safe_redirect(&redirect) {
            session
                .insert(OIDC_REDIRECT_KEY, redirect)
                .await
                .map_err(|e| ApiError::Internal(format!("failed to store redirect: {e}")))?;
        }
    }

    let mut auth_url = reqwest::Url::parse(&normalized.discovery.authorization_endpoint)
        .map_err(|e| ApiError::BadRequest(format!("invalid authorization endpoint: {e}")))?;
    auth_url
        .query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &normalized.base.client_id)
        .append_pair("redirect_uri", &normalized.base.redirect_uri)
        .append_pair("scope", &normalized.base.scopes.join(" "))
        .append_pair("state", &state)
        .append_pair("nonce", &nonce)
        .append_pair("code_challenge", &code_challenge)
        .append_pair("code_challenge_method", "S256");

    Ok(Redirect::to(auth_url.as_str()).into_response())
}

async fn callback(
    State(state): State<AppState>,
    session: Session,
    Query(query): Query<OidcCallbackQuery>,
) -> Result<Response, ApiError> {
    let stored_state: Option<String> = session
        .get(OIDC_STATE_KEY)
        .await
        .map_err(|e| ApiError::Internal(format!("failed to read oidc state: {e}")))?;
    let stored_nonce: Option<String> = session
        .get(OIDC_NONCE_KEY)
        .await
        .map_err(|e| ApiError::Internal(format!("failed to read oidc nonce: {e}")))?;
    let code_verifier: Option<String> = session
        .get(OIDC_CODE_VERIFIER_KEY)
        .await
        .map_err(|e| ApiError::Internal(format!("failed to read oidc verifier: {e}")))?;
    let provider_name: Option<String> = session
        .get(OIDC_PROVIDER_KEY)
        .await
        .map_err(|e| ApiError::Internal(format!("failed to read oidc provider: {e}")))?;

    let expected_state =
        stored_state.ok_or_else(|| ApiError::Unauthorized("missing OIDC state".to_string()))?;
    if !secure_equals(&expected_state, &query.state) {
        return Err(ApiError::Unauthorized("invalid OIDC state".to_string()));
    }
    let nonce =
        stored_nonce.ok_or_else(|| ApiError::Unauthorized("missing OIDC nonce".to_string()))?;
    let verifier = code_verifier
        .ok_or_else(|| ApiError::Unauthorized("missing OIDC code verifier".to_string()))?;
    let provider = provider_name.unwrap_or_else(|| "default".to_string());

    // One-time use values; clear them immediately.
    let _ = session.remove::<String>(OIDC_STATE_KEY).await;
    let _ = session.remove::<String>(OIDC_NONCE_KEY).await;
    let _ = session.remove::<String>(OIDC_CODE_VERIFIER_KEY).await;

    let config = load_oidc_config(&provider)?;
    let discovery = discover(&config).await?;
    let token_set = exchange_code_for_tokens(&config, &discovery, &query.code, &verifier).await?;
    if let Some(token_type) = token_set.token_type.as_deref() {
        if !token_type.eq_ignore_ascii_case("bearer") {
            warn!(token_type = %token_type, "Unexpected OIDC token type");
        }
    }
    let id_token = token_set.id_token.clone().ok_or_else(|| {
        ApiError::Unauthorized("OIDC provider did not return id_token".to_string())
    })?;

    let raw_claims = parse_jwt_payload(&id_token)?;
    validate_claims(&raw_claims, &config, &discovery, &nonce)?;

    let userinfo = if let Some(endpoint) = &discovery.userinfo_endpoint {
        fetch_userinfo(endpoint, &token_set.access_token).await.ok()
    } else {
        None
    };

    let claims = build_claims(&config.claims_mapping, &raw_claims, userinfo.as_ref())?;
    if !claims.active {
        return Err(ApiError::Unauthorized(
            "identity provider account is inactive".to_string(),
        ));
    }

    let require_mfa = std::env::var("TW_OIDC_REQUIRE_MFA")
        .ok()
        .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false);
    if require_mfa && !claims.mfa_verified {
        return Err(ApiError::Forbidden(
            "MFA is required by policy but was not present in IdP claims".to_string(),
        ));
    }

    let provisioner = UserProvisioner::default();
    provisioner
        .deprovision_if_inactive(&state.db, &claims)
        .await?;
    let user = provisioner
        .provision_from_claims(&state.db, &claims)
        .await?;

    if let Err(e) = session.cycle_id().await {
        warn!("Failed to cycle session ID after OIDC callback: {}", e);
    }

    let session_data = SessionData::new_sso(
        &user,
        provider.clone(),
        claims.subject.clone(),
        claims.mfa_verified,
        claims.session_id.clone(),
    );
    set_session_data(&session, session_data)
        .await
        .map_err(|e| ApiError::Internal(format!("failed to persist session: {e}")))?;

    if let Some(refresh) = token_set.refresh_token {
        let _ = session.insert(OIDC_REFRESH_TOKEN_KEY, refresh).await;
    }
    let _ = session.insert(OIDC_ID_TOKEN_KEY, id_token).await;
    if let Some(end_session) = discovery.end_session_endpoint {
        let _ = session.insert(OIDC_END_SESSION_KEY, end_session).await;
    }

    let user_repo = create_user_repository(&state.db);
    let _ = user_repo.update_last_login(user.id).await;

    info!(
        user_id = %user.id,
        username = %user.username,
        provider = %provider,
        mfa = claims.mfa_verified,
        "OIDC login completed"
    );

    let redirect_target = session
        .get::<String>(OIDC_REDIRECT_KEY)
        .await
        .ok()
        .flatten()
        .filter(|v| is_safe_redirect(v))
        .unwrap_or_else(|| "/".to_string());
    let _ = session.remove::<String>(OIDC_REDIRECT_KEY).await;

    Ok(Redirect::to(&redirect_target).into_response())
}

async fn logout(session: Session) -> Result<Response, ApiError> {
    let id_token_hint = session
        .get::<String>(OIDC_ID_TOKEN_KEY)
        .await
        .ok()
        .flatten();
    let end_session = session
        .get::<String>(OIDC_END_SESSION_KEY)
        .await
        .ok()
        .flatten();

    clear_session(&session)
        .await
        .map_err(|e| ApiError::Internal(format!("failed to clear session: {e}")))?;

    if let Some(endpoint) = end_session {
        let mut logout_url = reqwest::Url::parse(&endpoint)
            .map_err(|e| ApiError::BadRequest(format!("invalid end_session endpoint: {e}")))?;
        if let Some(id_token) = id_token_hint {
            logout_url
                .query_pairs_mut()
                .append_pair("id_token_hint", &id_token);
        }
        if let Ok(post_logout_redirect) = std::env::var("TW_OIDC_POST_LOGOUT_REDIRECT_URI") {
            logout_url
                .query_pairs_mut()
                .append_pair("post_logout_redirect_uri", &post_logout_redirect);
        }
        return Ok(Redirect::to(logout_url.as_str()).into_response());
    }

    Ok(Redirect::to("/login").into_response())
}

async fn refresh(session: Session) -> Result<Json<OidcRefreshResponse>, ApiError> {
    let provider: Option<String> = session
        .get(OIDC_PROVIDER_KEY)
        .await
        .map_err(|e| ApiError::Internal(format!("failed to read provider from session: {e}")))?;
    let refresh_token: Option<String> = session
        .get(OIDC_REFRESH_TOKEN_KEY)
        .await
        .map_err(|e| ApiError::Internal(format!("failed to read refresh token: {e}")))?;

    let provider =
        provider.ok_or_else(|| ApiError::Unauthorized("No OIDC provider in session".into()))?;
    let refresh_token = refresh_token
        .ok_or_else(|| ApiError::Unauthorized("No refresh token in session".into()))?;

    let config = load_oidc_config(&provider)?;
    let discovery = discover(&config).await?;
    let token_set = refresh_tokens(&config, &discovery, &refresh_token).await?;
    if let Some(token_type) = token_set.token_type.as_deref() {
        if !token_type.eq_ignore_ascii_case("bearer") {
            warn!(token_type = %token_type, "Unexpected refreshed token type");
        }
    }

    if let Some(new_refresh) = token_set.refresh_token {
        session
            .insert(OIDC_REFRESH_TOKEN_KEY, new_refresh)
            .await
            .map_err(|e| ApiError::Internal(format!("failed to update refresh token: {e}")))?;
    }
    if let Some(new_id) = token_set.id_token {
        session
            .insert(OIDC_ID_TOKEN_KEY, new_id)
            .await
            .map_err(|e| ApiError::Internal(format!("failed to update id token: {e}")))?;
    }

    Ok(Json(OidcRefreshResponse {
        refreshed: true,
        expires_in: token_set.expires_in,
    }))
}

fn load_oidc_config(provider: &str) -> Result<OidcConfig, ApiError> {
    let prefix = if provider == "default" {
        "TW_OIDC".to_string()
    } else {
        format!("TW_OIDC_{}", env_key(provider))
    };

    let issuer = env_required(&format!("{prefix}_ISSUER"))?;
    let client_id = env_required(&format!("{prefix}_CLIENT_ID"))?;
    let client_secret = env_required(&format!("{prefix}_CLIENT_SECRET"))?;
    let redirect_uri = env_required(&format!("{prefix}_REDIRECT_URI"))?;
    let scopes = std::env::var(format!("{prefix}_SCOPES"))
        .ok()
        .map(|value| {
            value
                .split(',')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        })
        .filter(|v| !v.is_empty())
        .unwrap_or_else(OidcConfig::default_scopes);

    let claims_mapping = ClaimsMapping {
        email_claim: std::env::var(format!("{prefix}_EMAIL_CLAIM"))
            .unwrap_or_else(|_| "email".into()),
        name_claim: std::env::var(format!("{prefix}_NAME_CLAIM")).unwrap_or_else(|_| "name".into()),
        groups_claim: std::env::var(format!("{prefix}_GROUPS_CLAIM"))
            .ok()
            .or(Some("groups".into())),
        roles_claim: std::env::var(format!("{prefix}_ROLES_CLAIM"))
            .ok()
            .or(Some("roles".into())),
        mfa_claim: std::env::var(format!("{prefix}_MFA_CLAIM"))
            .ok()
            .or(Some("amr".into())),
        subject_claim: std::env::var(format!("{prefix}_SUBJECT_CLAIM"))
            .unwrap_or_else(|_| "sub".into()),
        tenant_claim: std::env::var(format!("{prefix}_TENANT_CLAIM")).ok(),
    };

    Ok(OidcConfig {
        provider_name: provider.to_string(),
        issuer,
        client_id,
        client_secret: tw_core::SecureString::new(client_secret),
        redirect_uri,
        scopes,
        claims_mapping,
        authorization_endpoint: std::env::var(format!("{prefix}_AUTHORIZATION_ENDPOINT")).ok(),
        token_endpoint: std::env::var(format!("{prefix}_TOKEN_ENDPOINT")).ok(),
        userinfo_endpoint: std::env::var(format!("{prefix}_USERINFO_ENDPOINT")).ok(),
        end_session_endpoint: std::env::var(format!("{prefix}_END_SESSION_ENDPOINT")).ok(),
    })
}

async fn discover(config: &OidcConfig) -> Result<OidcDiscoveryDocument, ApiError> {
    if let (Some(auth), Some(token)) = (&config.authorization_endpoint, &config.token_endpoint) {
        return Ok(OidcDiscoveryDocument {
            issuer: config.issuer.clone(),
            authorization_endpoint: auth.clone(),
            token_endpoint: token.clone(),
            userinfo_endpoint: config.userinfo_endpoint.clone(),
            end_session_endpoint: config.end_session_endpoint.clone(),
        });
    }

    let issuer = config.issuer.trim_end_matches('/');
    let url = format!("{issuer}/.well-known/openid-configuration");
    let response = reqwest::Client::new()
        .get(&url)
        .send()
        .await
        .map_err(|e| ApiError::Internal(format!("failed OIDC discovery request: {e}")))?;
    if !response.status().is_success() {
        return Err(ApiError::BadRequest(format!(
            "OIDC discovery failed with status {}",
            response.status()
        )));
    }

    response
        .json::<OidcDiscoveryDocument>()
        .await
        .map_err(|e| ApiError::Internal(format!("failed to parse discovery document: {e}")))
}

async fn exchange_code_for_tokens(
    config: &OidcConfig,
    discovery: &OidcDiscoveryDocument,
    code: &str,
    code_verifier: &str,
) -> Result<OidcTokenResponse, ApiError> {
    let mut form = HashMap::new();
    form.insert("grant_type", "authorization_code".to_string());
    form.insert("code", code.to_string());
    form.insert("redirect_uri", config.redirect_uri.clone());
    form.insert("client_id", config.client_id.clone());
    form.insert(
        "client_secret",
        config.client_secret.expose_secret().to_string(),
    );
    form.insert("code_verifier", code_verifier.to_string());

    let response = reqwest::Client::new()
        .post(&discovery.token_endpoint)
        .form(&form)
        .send()
        .await
        .map_err(|e| ApiError::Internal(format!("failed token request: {e}")))?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(ApiError::Unauthorized(format!(
            "OIDC token exchange failed ({status}): {body}"
        )));
    }
    response
        .json::<OidcTokenResponse>()
        .await
        .map_err(|e| ApiError::Internal(format!("failed to parse token response: {e}")))
}

async fn refresh_tokens(
    config: &OidcConfig,
    discovery: &OidcDiscoveryDocument,
    refresh_token: &str,
) -> Result<OidcTokenResponse, ApiError> {
    let mut form = HashMap::new();
    form.insert("grant_type", "refresh_token".to_string());
    form.insert("refresh_token", refresh_token.to_string());
    form.insert("client_id", config.client_id.clone());
    form.insert(
        "client_secret",
        config.client_secret.expose_secret().to_string(),
    );

    let response = reqwest::Client::new()
        .post(&discovery.token_endpoint)
        .form(&form)
        .send()
        .await
        .map_err(|e| ApiError::Internal(format!("failed refresh request: {e}")))?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(ApiError::Unauthorized(format!(
            "OIDC token refresh failed ({status}): {body}"
        )));
    }
    response
        .json::<OidcTokenResponse>()
        .await
        .map_err(|e| ApiError::Internal(format!("failed to parse refresh response: {e}")))
}

async fn fetch_userinfo(endpoint: &str, access_token: &str) -> Result<Value, ApiError> {
    let response = reqwest::Client::new()
        .get(endpoint)
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|e| ApiError::Internal(format!("userinfo request failed: {e}")))?;
    if !response.status().is_success() {
        return Err(ApiError::Unauthorized(format!(
            "userinfo failed with status {}",
            response.status()
        )));
    }
    response
        .json::<Value>()
        .await
        .map_err(|e| ApiError::Internal(format!("failed to parse userinfo response: {e}")))
}

fn build_claims(
    mapping: &ClaimsMapping,
    id_token: &Value,
    userinfo: Option<&Value>,
) -> Result<SsoClaims, ApiError> {
    let get_value = |key: &str| {
        id_token
            .get(key)
            .cloned()
            .or_else(|| userinfo.and_then(|u| u.get(key).cloned()))
    };
    let get_str = |key: &str| get_value(key).and_then(|v| v.as_str().map(ToString::to_string));

    let subject = get_str(&mapping.subject_claim)
        .ok_or_else(|| ApiError::Unauthorized("missing OIDC subject claim".to_string()))?;
    let email = get_str(&mapping.email_claim)
        .ok_or_else(|| ApiError::Unauthorized("missing OIDC email claim".to_string()))?;
    let display_name = get_str(&mapping.name_claim);

    let groups = mapping
        .groups_claim
        .as_deref()
        .and_then(get_value)
        .map(|v| claim_values(&v))
        .unwrap_or_default();
    let roles = mapping
        .roles_claim
        .as_deref()
        .and_then(get_value)
        .map(|v| claim_values(&v))
        .unwrap_or_default();

    let tenant_id = mapping
        .tenant_claim
        .as_deref()
        .and_then(get_str)
        .and_then(|value| Uuid::parse_str(&value).ok());

    let active = get_value("active")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let session_id = get_str("sid");

    let mfa_verified = if let Some(claim_name) = mapping.mfa_claim.as_deref() {
        get_value(claim_name)
            .map(|v| is_mfa_claim(&v))
            .unwrap_or(false)
    } else {
        false
    };

    Ok(SsoClaims {
        subject,
        email,
        display_name,
        groups,
        roles,
        tenant_id,
        active,
        mfa_verified,
        session_id,
    })
}

fn validate_claims(
    claims: &Value,
    config: &OidcConfig,
    discovery: &OidcDiscoveryDocument,
    expected_nonce: &str,
) -> Result<(), ApiError> {
    let issuer = claims
        .get("iss")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::Unauthorized("missing issuer claim".to_string()))?;
    let expected_issuer = discovery.issuer.trim_end_matches('/');
    if issuer.trim_end_matches('/') != expected_issuer {
        return Err(ApiError::Unauthorized(
            "OIDC issuer validation failed".to_string(),
        ));
    }

    let aud_valid = match claims.get("aud") {
        Some(Value::String(value)) => secure_equals(value, &config.client_id),
        Some(Value::Array(values)) => values
            .iter()
            .filter_map(Value::as_str)
            .any(|value| secure_equals(value, &config.client_id)),
        _ => false,
    };
    if !aud_valid {
        return Err(ApiError::Unauthorized(
            "OIDC audience validation failed".to_string(),
        ));
    }

    let nonce = claims
        .get("nonce")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::Unauthorized("missing nonce claim".to_string()))?;
    if !secure_equals(nonce, expected_nonce) {
        return Err(ApiError::Unauthorized(
            "OIDC nonce validation failed".to_string(),
        ));
    }

    if let Some(exp) = claims.get("exp").and_then(Value::as_i64) {
        if exp <= Utc::now().timestamp() {
            return Err(ApiError::Unauthorized("OIDC token expired".to_string()));
        }
    } else {
        return Err(ApiError::Unauthorized(
            "missing token expiration claim".to_string(),
        ));
    }

    Ok(())
}

fn parse_jwt_payload(id_token: &str) -> Result<Value, ApiError> {
    let mut segments = id_token.split('.');
    let _header = segments
        .next()
        .ok_or_else(|| ApiError::Unauthorized("invalid id_token header".to_string()))?;
    let payload = segments
        .next()
        .ok_or_else(|| ApiError::Unauthorized("invalid id_token payload".to_string()))?;
    let decoded = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|e| ApiError::Unauthorized(format!("invalid id_token encoding: {e}")))?;
    serde_json::from_slice(&decoded)
        .map_err(|e| ApiError::Unauthorized(format!("invalid id_token json: {e}")))
}

fn claim_values(value: &Value) -> Vec<String> {
    match value {
        Value::Array(items) => items
            .iter()
            .filter_map(Value::as_str)
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
        Value::String(s) => s
            .split([',', ';', ' '])
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(ToString::to_string)
            .collect(),
        _ => Vec::new(),
    }
}

fn is_mfa_claim(value: &Value) -> bool {
    match value {
        Value::Bool(v) => *v,
        Value::String(v) => {
            let normalized = v.to_ascii_lowercase();
            normalized.contains("mfa")
                || normalized.contains("otp")
                || normalized.contains("fido")
                || normalized.contains("webauthn")
                || normalized.contains("hardware")
                || normalized.contains("2fa")
        }
        Value::Array(items) => items.iter().any(is_mfa_claim),
        _ => false,
    }
}

fn pkce_challenge(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

fn env_required(key: &str) -> Result<String, ApiError> {
    std::env::var(key)
        .map_err(|_| ApiError::BadRequest(format!("Missing environment variable: {key}")))
}

fn random_token(len: usize) -> String {
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    (0..len)
        .map(|_| CHARSET[OsRng.gen_range(0..CHARSET.len())] as char)
        .collect()
}

fn env_key(provider: &str) -> String {
    provider
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect()
}

fn secure_equals(left: &str, right: &str) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.as_bytes().ct_eq(right.as_bytes()).into()
}

fn is_safe_redirect(path: &str) -> bool {
    path.starts_with('/') && !path.starts_with("//")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_claim_values_from_array_and_string() {
        let array_values = claim_values(&serde_json::json!(["a", "b"]));
        assert_eq!(array_values, vec!["a", "b"]);

        let string_values = claim_values(&serde_json::json!("x,y z"));
        assert_eq!(string_values, vec!["x", "y", "z"]);
    }

    #[test]
    fn test_pkce_challenge_generation() {
        let challenge = pkce_challenge("test-verifier");
        assert!(!challenge.is_empty());
        assert!(!challenge.contains('='));
    }

    #[test]
    fn test_env_key_normalization() {
        assert_eq!(env_key("okta-prod"), "OKTA_PROD");
        assert_eq!(env_key("tenant 1"), "TENANT_1");
    }

    #[test]
    fn test_mfa_claim_detection() {
        assert!(is_mfa_claim(&serde_json::json!(true)));
        assert!(is_mfa_claim(&serde_json::json!("webauthn")));
        assert!(is_mfa_claim(&serde_json::json!(["pwd", "mfa"])));
        assert!(!is_mfa_claim(&serde_json::json!("pwd")));
    }
}
