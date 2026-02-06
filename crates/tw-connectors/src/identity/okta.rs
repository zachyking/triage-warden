//! Okta identity provider connector.

use crate::http::HttpClient;
use crate::traits::{
    ActionResult, AuthLogEntry, ConnectorCategory, ConnectorError, ConnectorHealth,
    ConnectorResult, IdentityConnector, IdentityUser, TimeRange,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{info, instrument};

/// Okta connector configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OktaConfig {
    #[serde(flatten)]
    pub connector: crate::traits::ConnectorConfig,
    /// Okta org domain (e.g., "myorg.okta.com").
    pub domain: String,
}

/// Okta identity provider connector.
pub struct OktaConnector {
    config: OktaConfig,
    client: HttpClient,
}

impl OktaConnector {
    pub fn new(config: OktaConfig) -> ConnectorResult<Self> {
        let client = HttpClient::new(config.connector.clone())?;
        info!("Okta connector initialized for domain '{}'", config.domain);
        Ok(Self { config, client })
    }

    fn parse_user(user: &OktaUser) -> IdentityUser {
        let profile = &user.profile;
        IdentityUser {
            id: user.id.clone(),
            username: profile.login.clone(),
            email: profile.email.clone(),
            display_name: Some(
                format!(
                    "{} {}",
                    profile.first_name.as_deref().unwrap_or(""),
                    profile.last_name.as_deref().unwrap_or("")
                )
                .trim()
                .to_string(),
            ),
            active: user.status.as_deref() == Some("ACTIVE"),
            mfa_enabled: None,
            last_login: user
                .last_login
                .as_ref()
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|dt| dt.with_timezone(&Utc)),
            groups: Vec::new(),
            status: user.status.clone().unwrap_or_else(|| "unknown".to_string()),
            attributes: HashMap::new(),
        }
    }
}

#[async_trait]
impl crate::traits::Connector for OktaConnector {
    fn name(&self) -> &str {
        &self.config.connector.name
    }
    fn connector_type(&self) -> &str {
        "identity"
    }
    fn category(&self) -> ConnectorCategory {
        ConnectorCategory::Identity
    }
    fn capabilities(&self) -> Vec<String> {
        vec![
            "health_check",
            "test_connection",
            "get_user",
            "search_users",
            "get_auth_logs",
            "suspend_user",
            "reset_mfa",
            "revoke_sessions",
        ]
        .into_iter()
        .map(String::from)
        .collect()
    }

    async fn health_check(&self) -> ConnectorResult<ConnectorHealth> {
        match self.client.get("/api/v1/org").await {
            Ok(r) if r.status().is_success() => Ok(ConnectorHealth::Healthy),
            Ok(r) if r.status().as_u16() == 401 => {
                Ok(ConnectorHealth::Unhealthy("Auth failed".into()))
            }
            Ok(_) => Ok(ConnectorHealth::Degraded("Unexpected response".into())),
            Err(ConnectorError::ConnectionFailed(e)) => Ok(ConnectorHealth::Unhealthy(format!(
                "Connection failed: {}",
                e
            ))),
            Err(e) => Ok(ConnectorHealth::Unhealthy(e.to_string())),
        }
    }

    async fn test_connection(&self) -> ConnectorResult<bool> {
        let r = self.client.get("/api/v1/org").await?;
        Ok(r.status().is_success())
    }
}

#[async_trait]
impl IdentityConnector for OktaConnector {
    #[instrument(skip(self))]
    async fn get_user(&self, identifier: &str) -> ConnectorResult<IdentityUser> {
        let path = format!("/api/v1/users/{}", urlencoding::encode(identifier));
        let response = self.client.get(&path).await?;
        if !response.status().is_success() {
            return Err(ConnectorError::NotFound(format!(
                "User not found: {}",
                identifier
            )));
        }
        let user: OktaUser = response
            .json()
            .await
            .map_err(|e| ConnectorError::InvalidResponse(format!("Failed to parse user: {}", e)))?;
        Ok(Self::parse_user(&user))
    }

    async fn search_users(&self, query: &str, limit: usize) -> ConnectorResult<Vec<IdentityUser>> {
        let path = format!(
            "/api/v1/users?q={}&limit={}",
            urlencoding::encode(query),
            limit
        );
        let response = self.client.get(&path).await?;
        if !response.status().is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(ConnectorError::RequestFailed(format!(
                "Failed to search users: {}",
                body
            )));
        }
        let users: Vec<OktaUser> = response.json().await.map_err(|e| {
            ConnectorError::InvalidResponse(format!("Failed to parse users: {}", e))
        })?;
        Ok(users.iter().map(Self::parse_user).collect())
    }

    async fn get_user_groups(&self, user_id: &str) -> ConnectorResult<Vec<String>> {
        let path = format!("/api/v1/users/{}/groups", urlencoding::encode(user_id));
        let response = self.client.get(&path).await?;
        if !response.status().is_success() {
            return Err(ConnectorError::RequestFailed("Failed to get groups".into()));
        }
        let groups: Vec<OktaGroup> = response.json().await.map_err(|e| {
            ConnectorError::InvalidResponse(format!("Failed to parse groups: {}", e))
        })?;
        Ok(groups.into_iter().map(|g| g.profile.name).collect())
    }

    async fn get_auth_logs(
        &self,
        user_id: &str,
        timerange: TimeRange,
        limit: usize,
    ) -> ConnectorResult<Vec<AuthLogEntry>> {
        let path = format!(
            "/api/v1/logs?filter=actor.id eq \"{}\"&since={}&until={}&limit={}",
            user_id,
            timerange.start.format("%Y-%m-%dT%H:%M:%SZ"),
            timerange.end.format("%Y-%m-%dT%H:%M:%SZ"),
            limit
        );
        let response = self.client.get(&path).await?;
        if !response.status().is_success() {
            return Err(ConnectorError::RequestFailed("Failed to get logs".into()));
        }
        let events: Vec<OktaLogEvent> = response
            .json()
            .await
            .map_err(|e| ConnectorError::InvalidResponse(format!("Failed to parse logs: {}", e)))?;
        Ok(events
            .iter()
            .map(|e| AuthLogEntry {
                id: e.uuid.clone(),
                timestamp: e
                    .published
                    .as_ref()
                    .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(Utc::now),
                user: user_id.to_string(),
                result: e
                    .outcome
                    .as_ref()
                    .map(|o| o.result.clone())
                    .unwrap_or_default(),
                source_ip: e.client.as_ref().and_then(|c| c.ip_address.clone()),
                client_info: e.client.as_ref().and_then(|c| {
                    c.user_agent
                        .as_ref()
                        .map(|u| u.raw_user_agent.clone().unwrap_or_default())
                }),
                factor: None,
                details: HashMap::new(),
            })
            .collect())
    }

    async fn suspend_user(&self, user_id: &str) -> ConnectorResult<ActionResult> {
        let path = format!(
            "/api/v1/users/{}/lifecycle/suspend",
            urlencoding::encode(user_id)
        );
        let response = self.client.post(&path, &serde_json::json!({})).await?;
        Ok(ActionResult {
            success: response.status().is_success(),
            action_id: format!("okta-suspend-{}", user_id),
            message: if response.status().is_success() {
                format!("User {} suspended", user_id)
            } else {
                "Suspend failed".into()
            },
            timestamp: Utc::now(),
        })
    }

    async fn reset_mfa(&self, user_id: &str) -> ConnectorResult<ActionResult> {
        let path = format!(
            "/api/v1/users/{}/lifecycle/reset_factors",
            urlencoding::encode(user_id)
        );
        let response = self.client.post(&path, &serde_json::json!({})).await?;
        Ok(ActionResult {
            success: response.status().is_success(),
            action_id: format!("okta-reset-mfa-{}", user_id),
            message: if response.status().is_success() {
                format!("MFA reset for {}", user_id)
            } else {
                "Reset failed".into()
            },
            timestamp: Utc::now(),
        })
    }

    async fn revoke_sessions(&self, user_id: &str) -> ConnectorResult<ActionResult> {
        let path = format!("/api/v1/users/{}/sessions", urlencoding::encode(user_id));
        let response = self.client.delete(&path).await?;
        Ok(ActionResult {
            success: response.status().is_success(),
            action_id: format!("okta-revoke-sessions-{}", user_id),
            message: if response.status().is_success() {
                format!("Sessions revoked for {}", user_id)
            } else {
                "Revoke failed".into()
            },
            timestamp: Utc::now(),
        })
    }
}

#[derive(Debug, Deserialize)]
struct OktaUser {
    id: String,
    status: Option<String>,
    profile: OktaProfile,
    #[serde(rename = "lastLogin")]
    last_login: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OktaProfile {
    login: String,
    email: Option<String>,
    #[serde(rename = "firstName")]
    first_name: Option<String>,
    #[serde(rename = "lastName")]
    last_name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OktaGroup {
    profile: OktaGroupProfile,
}

#[derive(Debug, Deserialize)]
struct OktaGroupProfile {
    name: String,
}

#[derive(Debug, Deserialize)]
struct OktaLogEvent {
    uuid: String,
    published: Option<String>,
    outcome: Option<OktaOutcome>,
    client: Option<OktaClient>,
}

#[derive(Debug, Deserialize)]
struct OktaOutcome {
    result: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OktaClient {
    ip_address: Option<String>,
    user_agent: Option<OktaUserAgent>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OktaUserAgent {
    raw_user_agent: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::test_connector_config;
    use crate::traits::Connector;

    fn create_test_config() -> OktaConfig {
        OktaConfig {
            connector: test_connector_config("okta-test", "https://myorg.okta.com"),
            domain: "myorg.okta.com".to_string(),
        }
    }

    #[test]
    fn test_connector_creation() {
        assert!(OktaConnector::new(create_test_config()).is_ok());
    }

    #[test]
    fn test_connector_name_and_category() {
        let c = OktaConnector::new(create_test_config()).unwrap();
        assert_eq!(c.name(), "okta-test");
        assert_eq!(c.category(), ConnectorCategory::Identity);
    }

    #[test]
    fn test_parse_user() {
        let user = OktaUser {
            id: "user-001".into(),
            status: Some("ACTIVE".into()),
            profile: OktaProfile {
                login: "jdoe".into(),
                email: Some("jdoe@co.com".into()),
                first_name: Some("John".into()),
                last_name: Some("Doe".into()),
            },
            last_login: Some("2024-01-15T10:30:00Z".into()),
        };
        let parsed = OktaConnector::parse_user(&user);
        assert_eq!(parsed.username, "jdoe");
        assert!(parsed.active);
        assert_eq!(parsed.display_name.as_deref(), Some("John Doe"));
    }

    #[test]
    fn test_capabilities() {
        let c = OktaConnector::new(create_test_config()).unwrap();
        assert!(c.capabilities().contains(&"suspend_user".to_string()));
    }
}
