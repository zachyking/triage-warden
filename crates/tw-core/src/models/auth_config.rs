//! Authentication provider configuration models.
//!
//! These models define persisted and runtime configuration for enterprise
//! identity provider integrations (OIDC and SAML).

use crate::SecureString;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// OpenID Connect provider configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcConfig {
    /// Human-readable provider identifier (e.g. "okta-prod").
    pub provider_name: String,
    /// Issuer URL for OIDC discovery and token validation.
    pub issuer: String,
    /// OAuth2 client ID.
    pub client_id: String,
    /// OAuth2 client secret.
    pub client_secret: SecureString,
    /// Redirect URI configured on the IdP.
    pub redirect_uri: String,
    /// Requested scopes.
    pub scopes: Vec<String>,
    /// Mapping from IdP claims to internal attributes.
    pub claims_mapping: ClaimsMapping,
    /// Optional explicit authorization endpoint override.
    pub authorization_endpoint: Option<String>,
    /// Optional explicit token endpoint override.
    pub token_endpoint: Option<String>,
    /// Optional explicit userinfo endpoint override.
    pub userinfo_endpoint: Option<String>,
    /// Optional explicit end-session endpoint override.
    pub end_session_endpoint: Option<String>,
}

impl OidcConfig {
    /// Returns a sane default scope set for enterprise login.
    pub fn default_scopes() -> Vec<String> {
        vec![
            "openid".to_string(),
            "profile".to_string(),
            "email".to_string(),
            "groups".to_string(),
        ]
    }
}

/// Mapping of claim names from IdP tokens into internal user attributes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimsMapping {
    /// Claim containing user email.
    pub email_claim: String,
    /// Claim containing display/full name.
    pub name_claim: String,
    /// Claim containing groups (array or delimited string).
    pub groups_claim: Option<String>,
    /// Claim containing roles (array or delimited string).
    pub roles_claim: Option<String>,
    /// Claim indicating MFA assurance (e.g. amr/acr).
    pub mfa_claim: Option<String>,
    /// Claim containing stable subject identifier.
    pub subject_claim: String,
    /// Optional claim containing external tenant identifier.
    pub tenant_claim: Option<String>,
}

impl Default for ClaimsMapping {
    fn default() -> Self {
        Self {
            email_claim: "email".to_string(),
            name_claim: "name".to_string(),
            groups_claim: Some("groups".to_string()),
            roles_claim: Some("roles".to_string()),
            mfa_claim: Some("amr".to_string()),
            subject_claim: "sub".to_string(),
            tenant_claim: None,
        }
    }
}

/// SAML service-provider configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlConfig {
    /// Human-readable provider identifier (e.g. "azuread-main").
    pub provider_name: String,
    /// SP Entity ID.
    pub entity_id: String,
    /// Assertion consumer service URL.
    pub acs_url: String,
    /// Optional SLO URL.
    pub slo_url: Option<String>,
    /// IdP metadata URL.
    pub idp_metadata_url: Option<String>,
    /// Inline IdP metadata XML.
    pub idp_metadata: Option<String>,
    /// IdP SSO URL.
    pub idp_sso_url: String,
    /// IdP SLO URL.
    pub idp_slo_url: Option<String>,
    /// IdP signing certificate in PEM form.
    pub certificate: String,
    /// SP private key in PEM form (for signed requests / decryption).
    pub private_key: SecureString,
    /// Mapping from SAML attributes to internal attributes.
    pub attribute_mapping: AttributeMapping,
}

/// Mapping of SAML attribute names to internal fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributeMapping {
    /// SAML attribute containing user email.
    pub email_attribute: String,
    /// SAML attribute containing display/full name.
    pub name_attribute: String,
    /// SAML attribute containing groups.
    pub groups_attribute: Option<String>,
    /// SAML attribute containing roles.
    pub roles_attribute: Option<String>,
    /// SAML attribute representing MFA assurance.
    pub mfa_attribute: Option<String>,
    /// SAML subject NameID format override.
    pub subject_nameid_format: Option<String>,
}

impl Default for AttributeMapping {
    fn default() -> Self {
        Self {
            email_attribute: "email".to_string(),
            name_attribute: "name".to_string(),
            groups_attribute: Some("groups".to_string()),
            roles_attribute: Some("roles".to_string()),
            mfa_attribute: Some("amr".to_string()),
            subject_nameid_format: None,
        }
    }
}

/// Runtime provider type.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthProviderType {
    /// OpenID Connect provider.
    Oidc,
    /// SAML provider.
    Saml,
}

/// Stored IdP configuration record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthProviderConfig {
    /// Provider identifier.
    pub provider_name: String,
    /// Provider protocol.
    pub provider_type: AuthProviderType,
    /// Whether this provider is enabled for login.
    pub enabled: bool,
    /// Whether this provider should enforce MFA claims.
    pub require_mfa: bool,
    /// Tenant-scoped role mapping from IdP groups/roles to internal role names.
    pub role_mapping: HashMap<String, String>,
    /// OIDC config payload when provider_type is OIDC.
    pub oidc: Option<OidcConfig>,
    /// SAML config payload when provider_type is SAML.
    pub saml: Option<SamlConfig>,
}

impl AuthProviderConfig {
    /// Returns true when this config has a valid payload for its type.
    pub fn is_valid(&self) -> bool {
        match self.provider_type {
            AuthProviderType::Oidc => self.oidc.is_some() && self.saml.is_none(),
            AuthProviderType::Saml => self.saml.is_some() && self.oidc.is_none(),
        }
    }
}
