//! Mock identity connector for testing.

use crate::traits::{
    ActionResult, AuthLogEntry, ConnectorCategory, ConnectorError, ConnectorHealth,
    ConnectorResult, IdentityConnector, IdentityUser, TimeRange,
};
use async_trait::async_trait;
use chrono::Utc;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct MockIdentityConnector {
    name: String,
    users: Arc<RwLock<HashMap<String, IdentityUser>>>,
}

impl MockIdentityConnector {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            users: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn with_sample_data(name: &str) -> Self {
        let mut users = HashMap::new();
        users.insert(
            "jdoe".to_string(),
            IdentityUser {
                id: "user-001".into(),
                username: "jdoe".into(),
                email: Some("jdoe@company.com".into()),
                display_name: Some("John Doe".into()),
                active: true,
                mfa_enabled: Some(true),
                last_login: Some(Utc::now()),
                groups: vec!["Engineering".into(), "VPN-Users".into()],
                status: "active".into(),
                attributes: HashMap::new(),
            },
        );
        users.insert(
            "admin".to_string(),
            IdentityUser {
                id: "user-002".into(),
                username: "admin".into(),
                email: Some("admin@company.com".into()),
                display_name: Some("Admin User".into()),
                active: true,
                mfa_enabled: Some(true),
                last_login: Some(Utc::now()),
                groups: vec!["Admins".into(), "Domain Admins".into()],
                status: "active".into(),
                attributes: HashMap::new(),
            },
        );
        Self {
            name: name.to_string(),
            users: Arc::new(RwLock::new(users)),
        }
    }

    pub async fn add_user(&self, user: IdentityUser) {
        self.users.write().await.insert(user.username.clone(), user);
    }
}

#[async_trait]
impl crate::traits::Connector for MockIdentityConnector {
    fn name(&self) -> &str {
        &self.name
    }
    fn connector_type(&self) -> &str {
        "identity"
    }
    fn category(&self) -> ConnectorCategory {
        ConnectorCategory::Identity
    }
    async fn health_check(&self) -> ConnectorResult<ConnectorHealth> {
        Ok(ConnectorHealth::Healthy)
    }
    async fn test_connection(&self) -> ConnectorResult<bool> {
        Ok(true)
    }
}

#[async_trait]
impl IdentityConnector for MockIdentityConnector {
    async fn get_user(&self, identifier: &str) -> ConnectorResult<IdentityUser> {
        let users = self.users.read().await;
        users
            .get(identifier)
            .or_else(|| {
                users
                    .values()
                    .find(|u| u.email.as_deref() == Some(identifier) || u.id == identifier)
            })
            .cloned()
            .ok_or_else(|| ConnectorError::NotFound(format!("User not found: {}", identifier)))
    }

    async fn search_users(&self, query: &str, limit: usize) -> ConnectorResult<Vec<IdentityUser>> {
        let users = self.users.read().await;
        let q = query.to_lowercase();
        Ok(users
            .values()
            .filter(|u| {
                u.username.to_lowercase().contains(&q)
                    || u.email.as_deref().unwrap_or("").to_lowercase().contains(&q)
            })
            .take(limit)
            .cloned()
            .collect())
    }

    async fn get_user_groups(&self, user_id: &str) -> ConnectorResult<Vec<String>> {
        let users = self.users.read().await;
        Ok(users
            .values()
            .find(|u| u.id == user_id || u.username == user_id)
            .map(|u| u.groups.clone())
            .unwrap_or_default())
    }

    async fn get_auth_logs(
        &self,
        _user_id: &str,
        _timerange: TimeRange,
        _limit: usize,
    ) -> ConnectorResult<Vec<AuthLogEntry>> {
        Ok(vec![AuthLogEntry {
            id: "log-001".into(),
            timestamp: Utc::now(),
            user: _user_id.into(),
            result: "SUCCESS".into(),
            source_ip: Some("192.168.1.100".into()),
            client_info: None,
            factor: Some("push".into()),
            details: HashMap::new(),
        }])
    }

    async fn suspend_user(&self, user_id: &str) -> ConnectorResult<ActionResult> {
        let mut users = self.users.write().await;
        if let Some(u) = users
            .values_mut()
            .find(|u| u.id == user_id || u.username == user_id)
        {
            u.active = false;
            u.status = "suspended".into();
        }
        Ok(ActionResult {
            success: true,
            action_id: format!("mock-suspend-{}", user_id),
            message: format!("User {} suspended", user_id),
            timestamp: Utc::now(),
        })
    }

    async fn reset_mfa(&self, user_id: &str) -> ConnectorResult<ActionResult> {
        Ok(ActionResult {
            success: true,
            action_id: format!("mock-reset-mfa-{}", user_id),
            message: format!("MFA reset for {}", user_id),
            timestamp: Utc::now(),
        })
    }

    async fn revoke_sessions(&self, user_id: &str) -> ConnectorResult<ActionResult> {
        Ok(ActionResult {
            success: true,
            action_id: format!("mock-revoke-{}", user_id),
            message: format!("Sessions revoked for {}", user_id),
            timestamp: Utc::now(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::Connector;

    #[tokio::test]
    async fn test_get_user() {
        let c = MockIdentityConnector::with_sample_data("test");
        let user = c.get_user("jdoe").await.unwrap();
        assert_eq!(user.username, "jdoe");
        assert!(user.active);
    }

    #[tokio::test]
    async fn test_suspend_user() {
        let c = MockIdentityConnector::with_sample_data("test");
        let result = c.suspend_user("jdoe").await.unwrap();
        assert!(result.success);
        let user = c.get_user("jdoe").await.unwrap();
        assert!(!user.active);
    }

    #[tokio::test]
    async fn test_search_users() {
        let c = MockIdentityConnector::with_sample_data("test");
        let results = c.search_users("admin", 10).await.unwrap();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_name_and_category() {
        let c = MockIdentityConnector::new("test");
        assert_eq!(c.name(), "test");
        assert_eq!(c.category(), ConnectorCategory::Identity);
    }
}
