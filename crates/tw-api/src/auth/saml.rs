//! SAML 2.0 Service Provider endpoints.
//!
//! This module implements pragmatic SAML support for enterprise IdPs including:
//! - SP metadata endpoint
//! - Login initiation endpoint
//! - Assertion Consumer Service (ACS)
//! - Single logout endpoint
//!
//! The ACS flow validates issuer/audience/time windows, enforces signed
//! assertions with certificate pinning, provisions users via JIT, and
//! tracks MFA assurance from SAML auth context.

use crate::auth::{clear_session, set_session_data};
use crate::error::ApiError;
use crate::state::AppState;
use axum::extract::{Form, Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{response::Html, Router};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chrono::{DateTime, Utc};
use regex::Regex;
use rust_xmlsec::{decode_and_verify_signed_document, Output as XmlSigOutput};
use serde::Deserialize;
use std::collections::HashMap;
use subtle::ConstantTimeEq;
use tower_sessions::Session;
use tracing::{info, warn};
use tw_core::auth::SessionData;
use tw_core::db::create_user_repository;
use tw_core::{AttributeMapping, SamlConfig, SecureString};

use super::provisioning::{SsoClaims, UserProvisioner};

const SAML_PROVIDER_KEY: &str = "saml_provider";
const SAML_RELAY_STATE_KEY: &str = "saml_relay_state";
const SAML_SESSION_INDEX_KEY: &str = "saml_session_index";
const SAML_REQUEST_ID_KEY: &str = "saml_request_id";

/// SAML route set mounted at `/auth/saml`.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/metadata", get(metadata))
        .route("/login", get(login))
        .route("/acs", post(acs))
        .route("/slo", get(slo).post(slo))
}

#[derive(Debug, Deserialize)]
struct SamlLoginQuery {
    relay_state: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SamlAcsForm {
    #[serde(rename = "SAMLResponse")]
    saml_response: String,
    #[serde(rename = "RelayState")]
    relay_state: Option<String>,
}

#[derive(Debug, Clone)]
struct ParsedSamlAssertion {
    issuer: String,
    subject: String,
    audience: String,
    destination: Option<String>,
    in_response_to: Option<String>,
    nameid_format: Option<String>,
    email: String,
    name: Option<String>,
    groups: Vec<String>,
    roles: Vec<String>,
    session_index: Option<String>,
    signature_method: Option<String>,
    digest_method: Option<String>,
    mfa_verified: bool,
    not_before: Option<DateTime<Utc>>,
    not_on_or_after: Option<DateTime<Utc>>,
    certificate: Option<String>,
    has_signature: bool,
    encrypted_assertion: bool,
    active: bool,
}

async fn metadata() -> Result<Html<String>, ApiError> {
    let cfg = load_saml_config()?;
    let slo_xml = cfg
        .slo_url
        .as_ref()
        .map(|url| {
            format!(
                r#"<SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="{url}" />"#
            )
        })
        .unwrap_or_default();

    let metadata = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{entity_id}">
  <SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>
    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{acs_url}" index="1" isDefault="true" />
    {slo_xml}
  </SPSSODescriptor>
</EntityDescriptor>"#,
        entity_id = escape_xml(&cfg.entity_id),
        acs_url = escape_xml(&cfg.acs_url),
        slo_xml = slo_xml
    );

    Ok(Html(metadata))
}

async fn login(
    session: Session,
    Query(query): Query<SamlLoginQuery>,
) -> Result<Response, ApiError> {
    let cfg = load_saml_config()?;
    let relay_state = query
        .relay_state
        .filter(|path| path.starts_with('/') && !path.starts_with("//"))
        .unwrap_or_else(|| "/".to_string());

    let request_id = format!("_{}", uuid::Uuid::new_v4().simple());
    let issue_instant = Utc::now().to_rfc3339();
    let authn_request = format!(
        r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="{id}" Version="2.0" IssueInstant="{issue_instant}" Destination="{dest}" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AssertionConsumerServiceURL="{acs}">
<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">{issuer}</saml:Issuer>
</samlp:AuthnRequest>"#,
        id = escape_xml(&request_id),
        issue_instant = escape_xml(&issue_instant),
        dest = escape_xml(&cfg.idp_sso_url),
        acs = escape_xml(&cfg.acs_url),
        issuer = escape_xml(&cfg.entity_id),
    );

    session
        .insert(SAML_PROVIDER_KEY, cfg.provider_name.clone())
        .await
        .map_err(|e| ApiError::Internal(format!("failed to persist saml provider: {e}")))?;
    session
        .insert(SAML_REQUEST_ID_KEY, request_id)
        .await
        .map_err(|e| ApiError::Internal(format!("failed to persist saml request id: {e}")))?;
    session
        .insert(SAML_RELAY_STATE_KEY, relay_state.clone())
        .await
        .map_err(|e| ApiError::Internal(format!("failed to persist relay state: {e}")))?;

    let encoded_request = STANDARD.encode(authn_request.as_bytes());
    let mut login_url = reqwest::Url::parse(&cfg.idp_sso_url)
        .map_err(|e| ApiError::BadRequest(format!("invalid idp sso url: {e}")))?;
    login_url
        .query_pairs_mut()
        .append_pair("SAMLRequest", &encoded_request)
        .append_pair("RelayState", &relay_state);

    Ok(Redirect::to(login_url.as_str()).into_response())
}

async fn acs(
    State(state): State<AppState>,
    session: Session,
    Form(form): Form<SamlAcsForm>,
) -> Result<Response, ApiError> {
    let cfg = load_saml_config()?;
    let expected_request_id = session
        .get::<String>(SAML_REQUEST_ID_KEY)
        .await
        .map_err(|e| ApiError::Internal(format!("failed to read SAML request id: {e}")))?;
    let stored_relay_state = session
        .get::<String>(SAML_RELAY_STATE_KEY)
        .await
        .map_err(|e| ApiError::Internal(format!("failed to read relay state: {e}")))?;

    let xml_bytes = STANDARD
        .decode(form.saml_response.as_bytes())
        .map_err(|e| ApiError::Unauthorized(format!("invalid base64 SAML response: {e}")))?;
    let xml = String::from_utf8(xml_bytes)
        .map_err(|e| ApiError::Unauthorized(format!("invalid SAML XML encoding: {e}")))?;

    let verified_xml = verify_saml_xmldsig(&xml)?;
    let parsed = parse_saml_assertion(&verified_xml, &cfg.attribute_mapping)?;
    validate_assertion(&parsed, &cfg, expected_request_id.as_deref())?;

    let claims = SsoClaims {
        subject: parsed.subject.clone(),
        email: parsed.email.clone(),
        display_name: parsed.name.clone(),
        groups: parsed.groups.clone(),
        roles: parsed.roles.clone(),
        tenant_id: None,
        active: parsed.active,
        mfa_verified: parsed.mfa_verified,
        session_id: parsed.session_index.clone(),
    };

    let require_mfa = std::env::var("TW_SAML_REQUIRE_MFA")
        .ok()
        .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false);
    if require_mfa && !claims.mfa_verified {
        return Err(ApiError::Forbidden(
            "MFA is required by policy but was not present in SAML assertion".to_string(),
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
        warn!("Failed to cycle session ID after SAML ACS: {}", e);
    }

    let data = SessionData::new_sso(
        &user,
        cfg.provider_name.clone(),
        claims.subject.clone(),
        claims.mfa_verified,
        claims.session_id.clone(),
    );
    set_session_data(&session, data)
        .await
        .map_err(|e| ApiError::Internal(format!("failed to persist session: {e}")))?;

    if let Some(session_index) = parsed.session_index {
        let _ = session.insert(SAML_SESSION_INDEX_KEY, session_index).await;
    }
    let _ = session.remove::<String>(SAML_REQUEST_ID_KEY).await;

    let user_repo = create_user_repository(&state.db);
    let _ = user_repo.update_last_login(user.id).await;

    info!(
        user_id = %user.id,
        provider = %cfg.provider_name,
        mfa = claims.mfa_verified,
        "SAML login completed"
    );

    let relay_state = resolve_relay_state(form.relay_state, stored_relay_state)?;
    let _ = session.remove::<String>(SAML_RELAY_STATE_KEY).await;

    Ok(Redirect::to(&relay_state).into_response())
}

async fn slo(session: Session) -> Result<Response, ApiError> {
    let cfg = load_saml_config()?;
    let session_index = session
        .get::<String>(SAML_SESSION_INDEX_KEY)
        .await
        .ok()
        .flatten();
    clear_session(&session)
        .await
        .map_err(|e| ApiError::Internal(format!("failed to clear session: {e}")))?;

    if let Some(idp_slo_url) = cfg.idp_slo_url {
        let request_id = format!("_{}", uuid::Uuid::new_v4().simple());
        let issue_instant = Utc::now().to_rfc3339();
        let logout_request = format!(
            r#"<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="{id}" Version="2.0" IssueInstant="{issue_instant}" Destination="{dest}">
<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">{issuer}</saml:Issuer>
{session_index_xml}
</samlp:LogoutRequest>"#,
            id = escape_xml(&request_id),
            issue_instant = escape_xml(&issue_instant),
            dest = escape_xml(&idp_slo_url),
            issuer = escape_xml(&cfg.entity_id),
            session_index_xml = session_index
                .map(|v| format!(
                    r#"<samlp:SessionIndex>{}</samlp:SessionIndex>"#,
                    escape_xml(&v)
                ))
                .unwrap_or_default()
        );

        let encoded = STANDARD.encode(logout_request.as_bytes());
        let mut redirect_url = reqwest::Url::parse(&idp_slo_url)
            .map_err(|e| ApiError::BadRequest(format!("invalid idp slo url: {e}")))?;
        redirect_url
            .query_pairs_mut()
            .append_pair("SAMLRequest", &encoded);
        return Ok(Redirect::to(redirect_url.as_str()).into_response());
    }

    Ok(Redirect::to("/login").into_response())
}

fn load_saml_config() -> Result<SamlConfig, ApiError> {
    let provider_name = std::env::var("TW_SAML_PROVIDER").unwrap_or_else(|_| "default".to_string());
    let entity_id = env_required("TW_SAML_ENTITY_ID")?;
    let acs_url = env_required("TW_SAML_ACS_URL")?;
    let idp_sso_url = env_required("TW_SAML_IDP_SSO_URL")?;
    let certificate = env_required("TW_SAML_CERTIFICATE")?;
    let private_key = std::env::var("TW_SAML_PRIVATE_KEY").unwrap_or_default();

    let attribute_mapping = AttributeMapping {
        email_attribute: std::env::var("TW_SAML_EMAIL_ATTRIBUTE")
            .unwrap_or_else(|_| "email".to_string()),
        name_attribute: std::env::var("TW_SAML_NAME_ATTRIBUTE")
            .unwrap_or_else(|_| "name".to_string()),
        groups_attribute: std::env::var("TW_SAML_GROUPS_ATTRIBUTE")
            .ok()
            .or(Some("groups".to_string())),
        roles_attribute: std::env::var("TW_SAML_ROLES_ATTRIBUTE")
            .ok()
            .or(Some("roles".to_string())),
        mfa_attribute: std::env::var("TW_SAML_MFA_ATTRIBUTE")
            .ok()
            .or(Some("amr".to_string())),
        subject_nameid_format: std::env::var("TW_SAML_SUBJECT_FORMAT").ok(),
    };

    Ok(SamlConfig {
        provider_name,
        entity_id,
        acs_url,
        slo_url: std::env::var("TW_SAML_SLO_URL").ok(),
        idp_metadata_url: std::env::var("TW_SAML_IDP_METADATA_URL").ok(),
        idp_metadata: std::env::var("TW_SAML_IDP_METADATA").ok(),
        idp_sso_url,
        idp_slo_url: std::env::var("TW_SAML_IDP_SLO_URL").ok(),
        certificate,
        private_key: SecureString::new(private_key),
        attribute_mapping,
    })
}

fn parse_saml_assertion(
    xml: &str,
    mapping: &AttributeMapping,
) -> Result<ParsedSamlAssertion, ApiError> {
    let issuer = extract_tag_text(xml, "Issuer")
        .ok_or_else(|| ApiError::Unauthorized("missing SAML issuer".to_string()))?;
    let subject = extract_tag_text(xml, "NameID")
        .ok_or_else(|| ApiError::Unauthorized("missing SAML NameID".to_string()))?;
    let nameid_format = extract_attribute_value(xml, "NameID", "Format");
    let audience = extract_tag_text(xml, "Audience")
        .ok_or_else(|| ApiError::Unauthorized("missing SAML audience".to_string()))?;
    let destination = extract_attribute_value(xml, "Response", "Destination")
        .or_else(|| extract_attribute_value(xml, "SubjectConfirmationData", "Recipient"));
    let in_response_to = extract_attribute_value(xml, "Response", "InResponseTo")
        .or_else(|| extract_attribute_value(xml, "SubjectConfirmationData", "InResponseTo"));

    let attrs = extract_attributes(xml);
    let email = attrs
        .get(&mapping.email_attribute)
        .and_then(|v| v.first())
        .cloned()
        .ok_or_else(|| ApiError::Unauthorized("missing SAML email attribute".to_string()))?;
    let name = attrs
        .get(&mapping.name_attribute)
        .and_then(|v| v.first())
        .cloned();

    let groups = mapping
        .groups_attribute
        .as_ref()
        .and_then(|key| attrs.get(key))
        .cloned()
        .unwrap_or_default();
    let roles = mapping
        .roles_attribute
        .as_ref()
        .and_then(|key| attrs.get(key))
        .cloned()
        .unwrap_or_default();
    let mfa_verified = mapping
        .mfa_attribute
        .as_ref()
        .and_then(|key| attrs.get(key))
        .map(|values| values.iter().any(|v| is_mfa_value(v)))
        .unwrap_or_else(|| {
            extract_tag_text(xml, "AuthnContextClassRef")
                .map(|v| is_mfa_value(&v))
                .unwrap_or(false)
        });

    let session_index = extract_attribute_value(xml, "AuthnStatement", "SessionIndex");
    let signature_method = extract_attribute_value(xml, "SignatureMethod", "Algorithm");
    let digest_method = extract_attribute_value(xml, "DigestMethod", "Algorithm");
    let not_before = extract_attribute_value(xml, "Conditions", "NotBefore")
        .and_then(|s| parse_saml_time(&s).ok());
    let not_on_or_after = extract_attribute_value(xml, "Conditions", "NotOnOrAfter")
        .and_then(|s| parse_saml_time(&s).ok());
    let certificate = extract_tag_text(xml, "X509Certificate");
    let has_signature = xml.contains("SignatureValue");
    let encrypted_assertion = xml.contains("EncryptedAssertion");
    let active = attrs
        .get("active")
        .and_then(|v| v.first())
        .map(|v| !matches!(v.to_ascii_lowercase().as_str(), "false" | "0" | "disabled"))
        .unwrap_or(true);

    Ok(ParsedSamlAssertion {
        issuer,
        subject,
        audience,
        destination,
        in_response_to,
        nameid_format,
        email,
        name,
        groups,
        roles,
        session_index,
        signature_method,
        digest_method,
        mfa_verified,
        not_before,
        not_on_or_after,
        certificate,
        has_signature,
        encrypted_assertion,
        active,
    })
}

fn validate_assertion(
    assertion: &ParsedSamlAssertion,
    cfg: &SamlConfig,
    expected_request_id: Option<&str>,
) -> Result<(), ApiError> {
    if assertion.audience != cfg.entity_id {
        return Err(ApiError::Unauthorized(
            "SAML audience validation failed".to_string(),
        ));
    }

    if let Some(expected) = expected_request_id {
        let response_to = assertion
            .in_response_to
            .as_deref()
            .ok_or_else(|| ApiError::Unauthorized("missing SAML InResponseTo".to_string()))?;
        if !secure_equals(response_to.trim(), expected.trim()) {
            return Err(ApiError::Unauthorized(
                "SAML request correlation failed (InResponseTo mismatch)".to_string(),
            ));
        }
    }

    if let Some(destination) = assertion.destination.as_deref() {
        if !secure_equals(
            destination.trim_end_matches('/').trim(),
            cfg.acs_url.trim_end_matches('/').trim(),
        ) {
            return Err(ApiError::Unauthorized(
                "SAML destination validation failed".to_string(),
            ));
        }
    }

    if let Ok(expected_issuer) = std::env::var("TW_SAML_EXPECTED_ISSUER") {
        if !secure_equals(assertion.issuer.trim(), expected_issuer.trim()) {
            return Err(ApiError::Unauthorized(
                "SAML issuer validation failed".to_string(),
            ));
        }
    }

    if let Some(expected_format) = cfg.attribute_mapping.subject_nameid_format.as_deref() {
        if let Some(actual_format) = assertion.nameid_format.as_deref() {
            if !secure_equals(actual_format.trim(), expected_format.trim()) {
                return Err(ApiError::Unauthorized(
                    "SAML NameID format validation failed".to_string(),
                ));
            }
        }
    }

    let now = Utc::now();
    if let Some(not_before) = assertion.not_before {
        if now < not_before {
            return Err(ApiError::Unauthorized(
                "SAML assertion not yet valid".to_string(),
            ));
        }
    }
    if let Some(not_on_or_after) = assertion.not_on_or_after {
        if now >= not_on_or_after {
            return Err(ApiError::Unauthorized(
                "SAML assertion has expired".to_string(),
            ));
        }
    }

    if assertion.encrypted_assertion && cfg.private_key.expose_secret().is_empty() {
        return Err(ApiError::Unauthorized(
            "Encrypted SAML assertions require configured private key".to_string(),
        ));
    }

    if !assertion.has_signature {
        return Err(ApiError::Unauthorized(
            "Unsigned SAML assertion rejected".to_string(),
        ));
    }
    let signature_method = assertion
        .signature_method
        .as_deref()
        .ok_or_else(|| ApiError::Unauthorized("Missing SAML signature method".to_string()))?;
    if !is_allowed_signature_method(signature_method) {
        return Err(ApiError::Unauthorized(
            "Unsupported SAML signature method".to_string(),
        ));
    }
    let digest_method = assertion
        .digest_method
        .as_deref()
        .ok_or_else(|| ApiError::Unauthorized("Missing SAML digest method".to_string()))?;
    if !is_allowed_digest_method(digest_method) {
        return Err(ApiError::Unauthorized(
            "Unsupported SAML digest method".to_string(),
        ));
    }

    let expected_cert = normalize_cert(&cfg.certificate);
    let actual_cert = assertion
        .certificate
        .as_deref()
        .map(normalize_cert)
        .ok_or_else(|| ApiError::Unauthorized("Missing SAML signing certificate".to_string()))?;
    if !secure_equals(&expected_cert, &actual_cert) {
        return Err(ApiError::Unauthorized(
            "SAML certificate pinning validation failed".to_string(),
        ));
    }

    Ok(())
}

fn verify_saml_xmldsig(xml: &str) -> Result<String, ApiError> {
    match decode_and_verify_signed_document(xml)
        .map_err(|e| ApiError::Unauthorized(format!("SAML XMLDSIG verification failed: {e}")))?
    {
        XmlSigOutput::Verified { references, .. } => select_signed_reference(references)
            .ok_or_else(|| ApiError::Unauthorized("missing signed SAML reference".to_string())),
        XmlSigOutput::Unsigned(_) => Err(ApiError::Unauthorized(
            "Unsigned SAML assertion rejected".to_string(),
        )),
    }
}

fn select_signed_reference(references: Vec<String>) -> Option<String> {
    let mut fallback = None;
    for reference in references {
        let normalized = reference.to_ascii_lowercase();
        if normalized.contains("<assertion") || normalized.contains(":assertion") {
            return Some(reference);
        }
        if fallback.is_none() {
            fallback = Some(reference);
        }
    }
    fallback
}

fn parse_saml_time(value: &str) -> Result<DateTime<Utc>, ApiError> {
    DateTime::parse_from_rfc3339(value)
        .map(|v| v.with_timezone(&Utc))
        .map_err(|e| ApiError::Unauthorized(format!("invalid SAML timestamp: {e}")))
}

fn extract_tag_text(xml: &str, tag: &str) -> Option<String> {
    let escaped_tag = regex::escape(tag);
    let pattern = format!(r"(?s)<(?:\w+:)?{escaped_tag}\b[^>]*>(.*?)</(?:\w+:)?{escaped_tag}>");
    let re = Regex::new(&pattern).ok()?;
    re.captures(xml)
        .and_then(|caps| caps.get(1))
        .map(|m| m.as_str().trim().to_string())
}

fn extract_attribute_value(xml: &str, tag: &str, attribute: &str) -> Option<String> {
    let escaped_tag = regex::escape(tag);
    let escaped_attr = regex::escape(attribute);
    let pattern = format!(r#"(?s)<(?:\w+:)?{escaped_tag}\b[^>]*\b{escaped_attr}="([^"]+)"[^>]*>"#);
    let re = Regex::new(&pattern).ok()?;
    re.captures(xml)
        .and_then(|caps| caps.get(1))
        .map(|m| m.as_str().to_string())
}

fn extract_attributes(xml: &str) -> HashMap<String, Vec<String>> {
    let mut map = HashMap::new();
    let attr_re = match Regex::new(
        r#"(?s)<(?:\w+:)?Attribute\b[^>]*\bName="([^"]+)"[^>]*>(.*?)</(?:\w+:)?Attribute>"#,
    ) {
        Ok(re) => re,
        Err(_) => return map,
    };
    let value_re = match Regex::new(
        r#"(?s)<(?:\w+:)?AttributeValue\b[^>]*>(.*?)</(?:\w+:)?AttributeValue>"#,
    ) {
        Ok(re) => re,
        Err(_) => return map,
    };

    for attr_caps in attr_re.captures_iter(xml) {
        let Some(name_match) = attr_caps.get(1) else {
            continue;
        };
        let Some(body_match) = attr_caps.get(2) else {
            continue;
        };

        let mut values = Vec::new();
        for value_caps in value_re.captures_iter(body_match.as_str()) {
            if let Some(value_match) = value_caps.get(1) {
                let value = value_match.as_str().trim();
                if !value.is_empty() {
                    values.push(value.to_string());
                }
            }
        }

        if !values.is_empty() {
            map.entry(name_match.as_str().to_string())
                .or_insert_with(Vec::new)
                .extend(values);
        }
    }

    map
}

fn normalize_cert(cert: &str) -> String {
    cert.lines()
        .map(str::trim)
        .filter(|line| {
            !line.is_empty()
                && !line.starts_with("-----BEGIN CERTIFICATE-----")
                && !line.starts_with("-----END CERTIFICATE-----")
        })
        .collect::<String>()
}

fn secure_equals(left: &str, right: &str) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.as_bytes().ct_eq(right.as_bytes()).into()
}

fn is_mfa_value(value: &str) -> bool {
    let normalized = value.to_ascii_lowercase();
    normalized.contains("mfa")
        || normalized.contains("2fa")
        || normalized.contains("otp")
        || normalized.contains("webauthn")
        || normalized.contains("fido")
        || normalized.contains("timesynctoken")
        || normalized.contains("smartcard")
        || normalized.contains("multifactor")
}

fn is_allowed_signature_method(value: &str) -> bool {
    let normalized = value.trim().to_ascii_lowercase();
    normalized.contains("rsa-sha256")
        || normalized.contains("rsa-sha384")
        || normalized.contains("rsa-sha512")
}

fn is_allowed_digest_method(value: &str) -> bool {
    let normalized = value.trim().to_ascii_lowercase();
    normalized.ends_with("sha256")
        || normalized.ends_with("sha384")
        || normalized.ends_with("sha512")
}

fn resolve_relay_state(
    provided: Option<String>,
    stored: Option<String>,
) -> Result<String, ApiError> {
    let resolved = match (provided, stored) {
        (Some(provided), Some(stored)) => {
            if !secure_equals(provided.as_str(), stored.as_str()) {
                return Err(ApiError::Unauthorized(
                    "SAML relay state validation failed".to_string(),
                ));
            }
            provided
        }
        (Some(provided), None) => provided,
        (None, Some(stored)) => stored,
        (None, None) => "/".to_string(),
    };

    if !is_safe_relay_state(&resolved) {
        return Err(ApiError::Unauthorized(
            "Invalid SAML relay state path".to_string(),
        ));
    }

    Ok(resolved)
}

fn is_safe_relay_state(path: &str) -> bool {
    if !path.starts_with('/') || path.starts_with("//") {
        return false;
    }

    if path.contains('\\') {
        return false;
    }

    if path.bytes().any(|byte| byte.is_ascii_control()) {
        return false;
    }

    // Defensive: reject scheme-like payloads even if they are prefixed by a slash.
    !path.to_ascii_lowercase().contains("://")
}

fn env_required(key: &str) -> Result<String, ApiError> {
    std::env::var(key)
        .map_err(|_| ApiError::BadRequest(format!("Missing environment variable: {key}")))
}

fn escape_xml(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_tag_text_namespace() {
        let xml = r#"<saml:Issuer>https://idp.example.com</saml:Issuer>"#;
        assert_eq!(
            extract_tag_text(xml, "Issuer"),
            Some("https://idp.example.com".to_string())
        );
    }

    #[test]
    fn test_extract_attributes() {
        let xml = r#"
<Attribute Name="groups"><AttributeValue>soc-admin</AttributeValue><AttributeValue>ir-team</AttributeValue></Attribute>
"#;
        let attrs = extract_attributes(xml);
        assert_eq!(
            attrs.get("groups"),
            Some(&vec!["soc-admin".to_string(), "ir-team".to_string()])
        );
    }

    #[test]
    fn test_extract_attributes_namespaced() {
        let xml = r#"
<saml:Attribute Name="groups">
  <saml:AttributeValue>soc-admin</saml:AttributeValue>
  <saml:AttributeValue>ir-team</saml:AttributeValue>
</saml:Attribute>
"#;
        let attrs = extract_attributes(xml);
        assert_eq!(
            attrs.get("groups"),
            Some(&vec!["soc-admin".to_string(), "ir-team".to_string()])
        );
    }

    #[test]
    fn test_normalize_cert() {
        let cert = "-----BEGIN CERTIFICATE-----\nABC\nDEF\n-----END CERTIFICATE-----";
        assert_eq!(normalize_cert(cert), "ABCDEF");
    }

    #[test]
    fn test_is_mfa_value() {
        assert!(is_mfa_value(
            "urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken"
        ));
        assert!(is_mfa_value("MFA"));
        assert!(!is_mfa_value("password"));
    }

    #[test]
    fn test_allowed_signature_and_digest_algorithms() {
        assert!(is_allowed_signature_method(
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
        ));
        assert!(!is_allowed_signature_method(
            "http://www.w3.org/2000/09/xmldsig#hmac-sha1"
        ));
        assert!(is_allowed_digest_method(
            "http://www.w3.org/2001/04/xmlenc#sha256"
        ));
        assert!(!is_allowed_digest_method(
            "http://www.w3.org/2000/09/xmldsig#sha1"
        ));
    }

    #[test]
    fn test_select_signed_reference_prefers_assertion() {
        let references = vec![
            "<Response><Issuer>idp</Issuer></Response>".to_string(),
            "<Assertion><NameID>user@example.com</NameID></Assertion>".to_string(),
        ];
        let selected = select_signed_reference(references);
        assert_eq!(
            selected,
            Some("<Assertion><NameID>user@example.com</NameID></Assertion>".to_string())
        );
    }

    #[test]
    fn test_resolve_relay_state_validation() {
        assert_eq!(
            resolve_relay_state(
                Some("/dashboard".to_string()),
                Some("/dashboard".to_string())
            )
            .ok(),
            Some("/dashboard".to_string())
        );
        assert!(resolve_relay_state(Some("https://evil.com".to_string()), None).is_err());
        assert!(resolve_relay_state(Some("/\\evil.com".to_string()), None).is_err());
        assert!(resolve_relay_state(Some("/path\nx".to_string()), None).is_err());
        assert!(resolve_relay_state(Some("/a".to_string()), Some("/b".to_string())).is_err());
    }
}
