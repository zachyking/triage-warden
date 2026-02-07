//! Auth0 identity provider connector.

use crate::http::HttpClient;
use crate::traits::{
    ActionResult, AuthLogEntry, ConnectorCategory, ConnectorError, ConnectorHealth,
    ConnectorResult, IdentityConnector, IdentityUser, TimeRange,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Auth0Config {
    #[serde(flatten)]
    pub connector: crate::traits::ConnectorConfig,
    pub domain: String,
}

pub struct Auth0Connector {
    config: Auth0Config,
    client: HttpClient,
}

impl Auth0Connector {
    pub fn new(config: Auth0Config) -> ConnectorResult<Self> {
        let client = HttpClient::new(config.connector.clone())?;
        info!("Auth0 connector initialized for domain '{}'", config.domain);
        Ok(Self { config, client })
    }
}

#[async_trait]
impl crate::traits::Connector for Auth0Connector {
    fn name(&self) -> &str {
        &self.config.connector.name
    }
    fn connector_type(&self) -> &str {
        "identity"
    }
    fn category(&self) -> ConnectorCategory {
        ConnectorCategory::Identity
    }

    async fn health_check(&self) -> ConnectorResult<ConnectorHealth> {
        match self.client.get("/api/v2/tenants/settings").await {
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
        let r = self.client.get("/api/v2/tenants/settings").await?;
        Ok(r.status().is_success())
    }
}

#[async_trait]
impl IdentityConnector for Auth0Connector {
    async fn get_user(&self, identifier: &str) -> ConnectorResult<IdentityUser> {
        let path = format!("/api/v2/users/{}", urlencoding::encode(identifier));
        let response = self.client.get(&path).await?;
        if !response.status().is_success() {
            return Err(ConnectorError::NotFound(format!(
                "User not found: {}",
                identifier
            )));
        }
        let user: Auth0User = response
            .json()
            .await
            .map_err(|e| ConnectorError::InvalidResponse(format!("Failed to parse user: {}", e)))?;
        Ok(IdentityUser {
            id: user.user_id,
            username: user.username.unwrap_or_default(),
            email: user.email,
            display_name: user.name,
            active: !user.blocked.unwrap_or(false),
            mfa_enabled: None,
            last_login: user
                .last_login
                .as_ref()
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|dt| dt.with_timezone(&Utc)),
            groups: Vec::new(),
            status: if user.blocked.unwrap_or(false) {
                "blocked".into()
            } else {
                "active".into()
            },
            attributes: HashMap::new(),
        })
    }

    async fn search_users(&self, query: &str, limit: usize) -> ConnectorResult<Vec<IdentityUser>> {
        let path = format!(
            "/api/v2/users?q={}&per_page={}",
            urlencoding::encode(query),
            limit
        );
        let response = self.client.get(&path).await?;
        if !response.status().is_success() {
            return Err(ConnectorError::RequestFailed("Search failed".into()));
        }
        let users: Vec<Auth0User> = response.json().await.map_err(|e| {
            ConnectorError::InvalidResponse(format!("Failed to parse users: {}", e))
        })?;
        Ok(users
            .into_iter()
            .map(|u| IdentityUser {
                id: u.user_id,
                username: u.username.unwrap_or_default(),
                email: u.email,
                display_name: u.name,
                active: !u.blocked.unwrap_or(false),
                mfa_enabled: None,
                last_login: None,
                groups: Vec::new(),
                status: if u.blocked.unwrap_or(false) {
                    "blocked".into()
                } else {
                    "active".into()
                },
                attributes: HashMap::new(),
            })
            .collect())
    }

    async fn get_user_groups(&self, user_id: &str) -> ConnectorResult<Vec<String>> {
        let path = format!("/api/v2/users/{}/roles", urlencoding::encode(user_id));
        let response = self.client.get(&path).await?;
        if !response.status().is_success() {
            return Ok(Vec::new());
        }
        let roles: Vec<Auth0Role> = response.json().await.unwrap_or_default();
        Ok(roles.into_iter().map(|r| r.name).collect())
    }

    async fn get_auth_logs(
        &self,
        user_id: &str,
        _timerange: TimeRange,
        limit: usize,
    ) -> ConnectorResult<Vec<AuthLogEntry>> {
        let path = format!(
            "/api/v2/users/{}/logs?per_page={}",
            urlencoding::encode(user_id),
            limit
        );
        let response = self.client.get(&path).await?;
        if !response.status().is_success() {
            return Ok(Vec::new());
        }
        let logs: Vec<Auth0Log> = response.json().await.unwrap_or_default();
        Ok(logs
            .into_iter()
            .map(|l| AuthLogEntry {
                id: l.log_id,
                timestamp: l
                    .date
                    .as_ref()
                    .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(Utc::now),
                user: user_id.to_string(),
                result: l.log_type.unwrap_or_default(),
                source_ip: l.ip,
                client_info: l.user_agent,
                factor: None,
                details: HashMap::new(),
            })
            .collect())
    }

    async fn suspend_user(&self, user_id: &str) -> ConnectorResult<ActionResult> {
        let path = format!("/api/v2/users/{}", urlencoding::encode(user_id));
        let body = serde_json::json!({"blocked": true});
        let response = self.client.put(&path, &body).await?;
        Ok(ActionResult {
            success: response.status().is_success(),
            action_id: format!("auth0-block-{}", user_id),
            message: format!("User {} blocked", user_id),
            timestamp: Utc::now(),
        })
    }

    async fn unsuspend_user(&self, user_id: &str) -> ConnectorResult<ActionResult> {
        let path = format!("/api/v2/users/{}", urlencoding::encode(user_id));
        let body = serde_json::json!({"blocked": false});
        let response = self.client.put(&path, &body).await?;
        Ok(ActionResult {
            success: response.status().is_success(),
            action_id: format!("auth0-unblock-{}", user_id),
            message: format!("User {} unblocked", user_id),
            timestamp: Utc::now(),
        })
    }

    async fn reset_mfa(&self, user_id: &str) -> ConnectorResult<ActionResult> {
        let path = format!(
            "/api/v2/users/{}/multifactor/actions/invalidate-remember-browser",
            urlencoding::encode(user_id)
        );
        let response = self.client.post(&path, &serde_json::json!({})).await?;
        Ok(ActionResult {
            success: response.status().is_success(),
            action_id: format!("auth0-reset-mfa-{}", user_id),
            message: format!("MFA reset for {}", user_id),
            timestamp: Utc::now(),
        })
    }

    async fn revoke_sessions(&self, user_id: &str) -> ConnectorResult<ActionResult> {
        let path = format!("/api/v2/users/{}/sessions", urlencoding::encode(user_id));
        let response = self.client.delete(&path).await?;
        Ok(ActionResult {
            success: response.status().is_success(),
            action_id: format!("auth0-revoke-{}", user_id),
            message: format!("Sessions revoked for {}", user_id),
            timestamp: Utc::now(),
        })
    }
}

#[derive(Debug, Deserialize)]
struct Auth0User {
    user_id: String,
    username: Option<String>,
    email: Option<String>,
    name: Option<String>,
    blocked: Option<bool>,
    last_login: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct Auth0Role {
    name: String,
}

#[derive(Debug, Default, Deserialize)]
struct Auth0Log {
    #[serde(rename = "_id")]
    log_id: String,
    date: Option<String>,
    #[serde(rename = "type")]
    log_type: Option<String>,
    ip: Option<String>,
    user_agent: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::test_connector_config;
    use crate::traits::Connector;

    #[test]
    fn test_connector_creation() {
        let c = Auth0Connector::new(Auth0Config {
            connector: test_connector_config("auth0-test", "https://myorg.auth0.com"),
            domain: "myorg.auth0.com".into(),
        });
        assert!(c.is_ok());
    }

    #[test]
    fn test_name_and_category() {
        let c = Auth0Connector::new(Auth0Config {
            connector: test_connector_config("auth0-test", "https://myorg.auth0.com"),
            domain: "myorg.auth0.com".into(),
        })
        .unwrap();
        assert_eq!(c.name(), "auth0-test");
        assert_eq!(c.category(), ConnectorCategory::Identity);
    }

    #[test]
    fn test_connector_type() {
        let c = Auth0Connector::new(Auth0Config {
            connector: test_connector_config("auth0-test", "https://myorg.auth0.com"),
            domain: "myorg.auth0.com".into(),
        })
        .unwrap();
        assert_eq!(c.connector_type(), "identity");
    }
}
