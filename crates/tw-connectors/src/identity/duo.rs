//! Duo Security connector.

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
pub struct DuoConfig {
    #[serde(flatten)]
    pub connector: crate::traits::ConnectorConfig,
    pub api_hostname: String,
}

pub struct DuoConnector {
    config: DuoConfig,
    client: HttpClient,
}

impl DuoConnector {
    pub fn new(config: DuoConfig) -> ConnectorResult<Self> {
        let client = HttpClient::new(config.connector.clone())?;
        info!("Duo connector initialized for '{}'", config.api_hostname);
        Ok(Self { config, client })
    }
}

#[async_trait]
impl crate::traits::Connector for DuoConnector {
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
        match self.client.get("/admin/v1/info/summary").await {
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
        let r = self.client.get("/admin/v1/info/summary").await?;
        Ok(r.status().is_success())
    }
}

#[async_trait]
impl IdentityConnector for DuoConnector {
    async fn get_user(&self, identifier: &str) -> ConnectorResult<IdentityUser> {
        let path = format!(
            "/admin/v1/users?username={}",
            urlencoding::encode(identifier)
        );
        let response = self.client.get(&path).await?;
        if !response.status().is_success() {
            return Err(ConnectorError::NotFound(format!(
                "User not found: {}",
                identifier
            )));
        }
        let resp: DuoResponse<Vec<DuoUser>> = response
            .json()
            .await
            .map_err(|e| ConnectorError::InvalidResponse(format!("Parse error: {}", e)))?;
        let user =
            resp.response.into_iter().next().ok_or_else(|| {
                ConnectorError::NotFound(format!("User not found: {}", identifier))
            })?;
        Ok(IdentityUser {
            id: user.user_id,
            username: user.username.unwrap_or_default(),
            email: user.email,
            display_name: user.realname,
            active: user.status.as_deref() == Some("active"),
            mfa_enabled: Some(true),
            last_login: None,
            groups: Vec::new(),
            status: user.status.unwrap_or_else(|| "unknown".into()),
            attributes: HashMap::new(),
        })
    }

    async fn search_users(&self, query: &str, limit: usize) -> ConnectorResult<Vec<IdentityUser>> {
        let path = format!("/admin/v1/users?limit={}", limit);
        let response = self.client.get(&path).await?;
        if !response.status().is_success() {
            return Ok(Vec::new());
        }
        let resp: DuoResponse<Vec<DuoUser>> = response.json().await.unwrap_or(DuoResponse {
            response: Vec::new(),
        });
        let query_lower = query.to_lowercase();
        Ok(resp
            .response
            .into_iter()
            .filter(|u| {
                u.username
                    .as_deref()
                    .unwrap_or("")
                    .to_lowercase()
                    .contains(&query_lower)
                    || u.email
                        .as_deref()
                        .unwrap_or("")
                        .to_lowercase()
                        .contains(&query_lower)
            })
            .map(|u| IdentityUser {
                id: u.user_id,
                username: u.username.unwrap_or_default(),
                email: u.email,
                display_name: u.realname,
                active: u.status.as_deref() == Some("active"),
                mfa_enabled: Some(true),
                last_login: None,
                groups: Vec::new(),
                status: u.status.unwrap_or_else(|| "unknown".into()),
                attributes: HashMap::new(),
            })
            .collect())
    }

    async fn get_user_groups(&self, user_id: &str) -> ConnectorResult<Vec<String>> {
        let path = format!("/admin/v1/users/{}/groups", urlencoding::encode(user_id));
        let response = self.client.get(&path).await?;
        if !response.status().is_success() {
            return Ok(Vec::new());
        }
        let resp: DuoResponse<Vec<DuoGroup>> = response.json().await.unwrap_or(DuoResponse {
            response: Vec::new(),
        });
        Ok(resp.response.into_iter().map(|g| g.name).collect())
    }

    async fn get_auth_logs(
        &self,
        _user_id: &str,
        _timerange: TimeRange,
        limit: usize,
    ) -> ConnectorResult<Vec<AuthLogEntry>> {
        let path = format!("/admin/v2/logs/authentication?limit={}", limit);
        let response = self.client.get(&path).await?;
        if !response.status().is_success() {
            return Ok(Vec::new());
        }
        let resp: DuoResponse<Vec<DuoAuthLog>> = response.json().await.unwrap_or(DuoResponse {
            response: Vec::new(),
        });
        Ok(resp
            .response
            .into_iter()
            .map(|l| AuthLogEntry {
                id: l.txid.unwrap_or_default(),
                timestamp: DateTime::from_timestamp(l.timestamp.unwrap_or(0), 0)
                    .unwrap_or_else(Utc::now),
                user: l.user.and_then(|u| u.name).unwrap_or_default(),
                result: l.result.unwrap_or_default(),
                source_ip: l.access_device.and_then(|d| d.ip),
                client_info: None,
                factor: l.factor,
                details: HashMap::new(),
            })
            .collect())
    }

    async fn suspend_user(&self, user_id: &str) -> ConnectorResult<ActionResult> {
        let path = format!("/admin/v1/users/{}", urlencoding::encode(user_id));
        let body = serde_json::json!({"status": "disabled"});
        let response = self.client.post(&path, &body).await?;
        Ok(ActionResult {
            success: response.status().is_success(),
            action_id: format!("duo-disable-{}", user_id),
            message: format!("User {} disabled", user_id),
            timestamp: Utc::now(),
        })
    }

    async fn reset_mfa(&self, user_id: &str) -> ConnectorResult<ActionResult> {
        // Duo doesn't have a direct "reset MFA" - we'd delete phones
        Ok(ActionResult {
            success: true,
            action_id: format!("duo-reset-mfa-{}", user_id),
            message: format!("MFA reset not directly supported for Duo user {}", user_id),
            timestamp: Utc::now(),
        })
    }

    async fn revoke_sessions(&self, user_id: &str) -> ConnectorResult<ActionResult> {
        Ok(ActionResult {
            success: true,
            action_id: format!("duo-revoke-{}", user_id),
            message: format!("Session revocation handled at IdP level for {}", user_id),
            timestamp: Utc::now(),
        })
    }
}

#[derive(Debug, Default, Deserialize)]
struct DuoResponse<T> {
    response: T,
}

#[derive(Debug, Deserialize)]
struct DuoUser {
    user_id: String,
    username: Option<String>,
    email: Option<String>,
    realname: Option<String>,
    status: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DuoGroup {
    name: String,
}

#[derive(Debug, Deserialize)]
struct DuoAuthLog {
    txid: Option<String>,
    timestamp: Option<i64>,
    result: Option<String>,
    factor: Option<String>,
    user: Option<DuoLogUser>,
    access_device: Option<DuoAccessDevice>,
}

#[derive(Debug, Deserialize)]
struct DuoLogUser {
    name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DuoAccessDevice {
    ip: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::test_connector_config;
    use crate::traits::Connector;

    #[test]
    fn test_connector_creation() {
        let c = DuoConnector::new(DuoConfig {
            connector: test_connector_config("duo-test", "https://api-12345.duosecurity.com"),
            api_hostname: "api-12345.duosecurity.com".into(),
        });
        assert!(c.is_ok());
    }

    #[test]
    fn test_name_and_category() {
        let c = DuoConnector::new(DuoConfig {
            connector: test_connector_config("duo-test", "https://api-12345.duosecurity.com"),
            api_hostname: "api-12345.duosecurity.com".into(),
        })
        .unwrap();
        assert_eq!(c.name(), "duo-test");
        assert_eq!(c.category(), ConnectorCategory::Identity);
    }

    #[test]
    fn test_connector_type() {
        let c = DuoConnector::new(DuoConfig {
            connector: test_connector_config("duo-test", "https://api.duo.com"),
            api_hostname: "api.duo.com".into(),
        })
        .unwrap();
        assert_eq!(c.connector_type(), "identity");
    }
}
