//! Jira ticketing connector.
//!
//! This module provides integration with Jira Cloud and Server for ticket creation
//! and management. Supports API v3 (Cloud) with fallback patterns for Server.

use crate::http::{HttpClient, RateLimitConfig};
use crate::traits::{
    ConnectorConfig, ConnectorError, ConnectorHealth, ConnectorResult, CreateTicketRequest,
    Ticket, TicketPriority, TicketStatus, TicketingConnector, UpdateTicketRequest,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info, instrument, warn};

/// Jira-specific configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JiraConfig {
    /// Base connector configuration.
    #[serde(flatten)]
    pub connector: ConnectorConfig,
    /// Jira project key.
    pub project_key: String,
    /// Default issue type (e.g., "Task", "Bug", "Incident").
    #[serde(default = "default_issue_type")]
    pub default_issue_type: String,
    /// Field mappings for custom fields (our field name -> Jira field ID).
    #[serde(default)]
    pub field_mappings: HashMap<String, String>,
    /// Priority mappings (our priority name -> Jira priority name).
    #[serde(default)]
    pub priority_mappings: HashMap<String, String>,
    /// Whether this is Jira Server (vs Cloud). Affects API behavior.
    #[serde(default)]
    pub is_server: bool,
    /// Optional component to add to created issues.
    pub default_component: Option<String>,
    /// Optional security level for created issues.
    pub security_level: Option<String>,
}

fn default_issue_type() -> String {
    "Task".to_string()
}

/// Jira connector for ticket management.
pub struct JiraConnector {
    config: JiraConfig,
    client: HttpClient,
}

impl JiraConnector {
    /// Creates a new Jira connector.
    pub fn new(config: JiraConfig) -> ConnectorResult<Self> {
        // Jira Cloud rate limits are generous but we add some protection
        let rate_limit = RateLimitConfig {
            max_requests: 100,
            period: std::time::Duration::from_secs(60),
            burst_size: 20,
        };

        let client = HttpClient::with_rate_limit(config.connector.clone(), Some(rate_limit))?;

        info!(
            "Jira connector initialized for project {} ({})",
            config.project_key,
            if config.is_server { "Server" } else { "Cloud" }
        );

        Ok(Self { config, client })
    }

    /// Maps our priority to Jira priority name.
    fn map_priority(&self, priority: TicketPriority) -> String {
        let default_name = match priority {
            TicketPriority::Lowest => "Lowest",
            TicketPriority::Low => "Low",
            TicketPriority::Medium => "Medium",
            TicketPriority::High => "High",
            TicketPriority::Highest => "Highest",
        };

        // Check custom mappings first
        let key = format!("{:?}", priority).to_lowercase();
        self.config
            .priority_mappings
            .get(&key)
            .cloned()
            .unwrap_or_else(|| default_name.to_string())
    }

    /// Parses a Jira issue response into our Ticket type.
    fn parse_issue(&self, issue: JiraIssue) -> Ticket {
        let fields = issue.fields;

        // Parse description - handle both ADF and plain text
        let description = fields
            .description
            .map(|d| self.extract_description_text(&d))
            .unwrap_or_default();

        Ticket {
            id: issue.id,
            key: issue.key.clone(),
            title: fields.summary,
            description,
            status: fields.status.name,
            priority: self.parse_priority(&fields.priority.name),
            assignee: fields.assignee.map(|a| a.display_name),
            reporter: fields.reporter.map(|r| r.display_name).unwrap_or_default(),
            labels: fields.labels,
            created_at: fields.created,
            updated_at: fields.updated,
            url: format!(
                "{}/browse/{}",
                self.client.base_url().trim_end_matches('/'),
                issue.key
            ),
            custom_fields: self.extract_custom_fields(&fields.custom_fields),
        }
    }

    /// Parse priority string to enum.
    fn parse_priority(&self, name: &str) -> TicketPriority {
        match name.to_lowercase().as_str() {
            "lowest" | "trivial" => TicketPriority::Lowest,
            "low" | "minor" => TicketPriority::Low,
            "high" | "major" => TicketPriority::High,
            "highest" | "critical" | "blocker" => TicketPriority::Highest,
            _ => TicketPriority::Medium,
        }
    }

    /// Extract text from ADF (Atlassian Document Format) or plain text.
    fn extract_description_text(&self, desc: &serde_json::Value) -> String {
        if let Some(text) = desc.as_str() {
            return text.to_string();
        }

        // Handle ADF format
        if let Some(content) = desc.get("content").and_then(|c| c.as_array()) {
            let mut text_parts: Vec<String> = Vec::new();
            for block in content {
                if let Some(inner_content) = block.get("content").and_then(|c| c.as_array()) {
                    for item in inner_content {
                        if let Some(text) = item.get("text").and_then(|t| t.as_str()) {
                            text_parts.push(text.to_string());
                        }
                    }
                }
            }
            return text_parts.join("\n");
        }

        String::new()
    }

    /// Extract custom fields from the raw response.
    fn extract_custom_fields(
        &self,
        raw: &HashMap<String, serde_json::Value>,
    ) -> HashMap<String, serde_json::Value> {
        let mut result = HashMap::new();

        // Reverse lookup - find our field names from Jira field IDs
        for (our_name, jira_id) in &self.config.field_mappings {
            if let Some(value) = raw.get(jira_id) {
                if !value.is_null() {
                    result.insert(our_name.clone(), value.clone());
                }
            }
        }

        result
    }

    /// Build the API path for the configured Jira version.
    fn api_path(&self, path: &str) -> String {
        if self.config.is_server {
            format!("/rest/api/2{}", path)
        } else {
            format!("/rest/api/3{}", path)
        }
    }

    /// Transitions an issue to a new status.
    #[instrument(skip(self))]
    async fn transition_issue(&self, ticket_id: &str, target_status: &str) -> ConnectorResult<()> {
        // First, get available transitions
        let path = self.api_path(&format!("/issue/{}/transitions", ticket_id));
        let response = self.client.get(&path).await?;

        if !response.status().is_success() {
            return Err(ConnectorError::RequestFailed(
                "Failed to get transitions".to_string(),
            ));
        }

        let transitions: JiraTransitionsResponse = response
            .json()
            .await
            .map_err(|e| ConnectorError::InvalidResponse(e.to_string()))?;

        // Find the transition that leads to the target status
        let transition = transitions
            .transitions
            .iter()
            .find(|t| t.to.name.eq_ignore_ascii_case(target_status))
            .ok_or_else(|| {
                let available: Vec<_> = transitions.transitions.iter().map(|t| &t.to.name).collect();
                ConnectorError::RequestFailed(format!(
                    "No transition available to status '{}'. Available: {:?}",
                    target_status, available
                ))
            })?;

        // Execute the transition
        let transition_request = serde_json::json!({
            "transition": { "id": transition.id }
        });

        let response = self.client.post(&path, &transition_request).await?;

        if !response.status().is_success() {
            let error = response.text().await.unwrap_or_default();
            return Err(ConnectorError::RequestFailed(format!(
                "Failed to transition issue: {}",
                error
            )));
        }

        info!("Transitioned {} to status '{}'", ticket_id, target_status);
        Ok(())
    }

    /// Add a watcher to an issue.
    #[instrument(skip(self))]
    pub async fn add_watcher(&self, ticket_id: &str, account_id: &str) -> ConnectorResult<()> {
        let path = self.api_path(&format!("/issue/{}/watchers", ticket_id));
        let body = serde_json::json!(account_id);

        let response = self.client.post(&path, &body).await?;

        if !response.status().is_success() {
            warn!("Failed to add watcher to {}: {}", ticket_id, response.status());
        }

        Ok(())
    }

    /// Link two issues together.
    #[instrument(skip(self))]
    pub async fn link_issues(
        &self,
        from_key: &str,
        to_key: &str,
        link_type: &str,
    ) -> ConnectorResult<()> {
        let path = self.api_path("/issueLink");
        let body = serde_json::json!({
            "type": { "name": link_type },
            "inwardIssue": { "key": from_key },
            "outwardIssue": { "key": to_key }
        });

        let response = self.client.post(&path, &body).await?;

        if !response.status().is_success() {
            let error = response.text().await.unwrap_or_default();
            return Err(ConnectorError::RequestFailed(format!(
                "Failed to link issues: {}",
                error
            )));
        }

        info!("Linked {} -> {} ({})", from_key, to_key, link_type);
        Ok(())
    }

    /// Get available link types.
    pub async fn get_link_types(&self) -> ConnectorResult<Vec<String>> {
        let path = self.api_path("/issueLinkType");
        let response = self.client.get(&path).await?;

        if !response.status().is_success() {
            return Err(ConnectorError::RequestFailed(
                "Failed to get link types".to_string(),
            ));
        }

        #[derive(Deserialize)]
        struct LinkTypesResponse {
            #[serde(rename = "issueLinkTypes")]
            issue_link_types: Vec<LinkType>,
        }

        #[derive(Deserialize)]
        struct LinkType {
            name: String,
        }

        let result: LinkTypesResponse = response
            .json()
            .await
            .map_err(|e| ConnectorError::InvalidResponse(e.to_string()))?;

        Ok(result.issue_link_types.into_iter().map(|lt| lt.name).collect())
    }

    /// Search for issues using JQL.
    #[instrument(skip(self))]
    pub async fn search_jql(&self, jql: &str, limit: usize) -> ConnectorResult<Vec<Ticket>> {
        let search_request = JiraSearchRequest {
            jql: jql.to_string(),
            max_results: limit as u32,
            fields: vec![
                "summary".to_string(),
                "description".to_string(),
                "status".to_string(),
                "priority".to_string(),
                "assignee".to_string(),
                "reporter".to_string(),
                "labels".to_string(),
                "created".to_string(),
                "updated".to_string(),
            ],
        };

        let path = self.api_path("/search");
        let response = self.client.post(&path, &search_request).await?;

        if !response.status().is_success() {
            let error = response.text().await.unwrap_or_default();
            return Err(ConnectorError::RequestFailed(format!(
                "Search failed: {}",
                error
            )));
        }

        let search_result: JiraSearchResponse = response
            .json()
            .await
            .map_err(|e| ConnectorError::InvalidResponse(e.to_string()))?;

        Ok(search_result
            .issues
            .into_iter()
            .map(|i| self.parse_issue(i))
            .collect())
    }
}

#[async_trait]
impl crate::traits::Connector for JiraConnector {
    fn name(&self) -> &str {
        &self.config.connector.name
    }

    fn connector_type(&self) -> &str {
        "ticketing"
    }

    async fn health_check(&self) -> ConnectorResult<ConnectorHealth> {
        let path = self.api_path("/myself");
        match self.client.get(&path).await {
            Ok(response) if response.status().is_success() => Ok(ConnectorHealth::Healthy),
            Ok(response) if response.status() == reqwest::StatusCode::UNAUTHORIZED => {
                Ok(ConnectorHealth::Unhealthy("Authentication failed".to_string()))
            }
            Ok(response) => Ok(ConnectorHealth::Degraded(format!(
                "Unexpected status: {}",
                response.status()
            ))),
            Err(ConnectorError::ConnectionFailed(e)) => {
                Ok(ConnectorHealth::Unhealthy(format!("Connection failed: {}", e)))
            }
            Err(e) => Ok(ConnectorHealth::Unhealthy(e.to_string())),
        }
    }

    async fn test_connection(&self) -> ConnectorResult<bool> {
        let path = self.api_path("/myself");
        let response = self.client.get(&path).await?;
        Ok(response.status().is_success())
    }
}

#[async_trait]
impl TicketingConnector for JiraConnector {
    #[instrument(skip(self, request), fields(title = %request.title))]
    async fn create_ticket(&self, request: CreateTicketRequest) -> ConnectorResult<Ticket> {
        let issue_type = if request.ticket_type.is_empty() {
            &self.config.default_issue_type
        } else {
            &request.ticket_type
        };

        // Build fields
        let mut fields = serde_json::json!({
            "project": { "key": self.config.project_key },
            "summary": request.title,
            "issuetype": { "name": issue_type },
            "priority": { "name": self.map_priority(request.priority) },
            "labels": request.labels
        });

        // Add description (ADF format for Cloud, plain text for Server)
        if !request.description.is_empty() {
            if self.config.is_server {
                fields["description"] = serde_json::json!(request.description);
            } else {
                fields["description"] = serde_json::json!(JiraDescription::text(&request.description));
            }
        }

        // Add assignee if specified
        if let Some(assignee) = &request.assignee {
            if self.config.is_server {
                fields["assignee"] = serde_json::json!({ "name": assignee });
            } else {
                fields["assignee"] = serde_json::json!({ "accountId": assignee });
            }
        }

        // Add component if configured
        if let Some(component) = &self.config.default_component {
            fields["components"] = serde_json::json!([{ "name": component }]);
        }

        // Add security level if configured
        if let Some(security) = &self.config.security_level {
            fields["security"] = serde_json::json!({ "name": security });
        }

        // Add custom fields
        for (our_name, value) in &request.custom_fields {
            if let Some(jira_field) = self.config.field_mappings.get(our_name) {
                fields[jira_field] = value.clone();
            }
        }

        let create_request = serde_json::json!({ "fields": fields });

        let path = self.api_path("/issue");
        let response = self.client.post(&path, &create_request).await?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(ConnectorError::RequestFailed(format!(
                "Failed to create issue: {}",
                error_text
            )));
        }

        let created: JiraCreateResponse = response
            .json()
            .await
            .map_err(|e| ConnectorError::InvalidResponse(e.to_string()))?;

        info!("Created Jira issue: {} (id: {})", created.key, created.id);

        // Fetch the full issue details
        self.get_ticket(&created.key).await
    }

    #[instrument(skip(self), fields(ticket_id = %ticket_id))]
    async fn get_ticket(&self, ticket_id: &str) -> ConnectorResult<Ticket> {
        let path = self.api_path(&format!("/issue/{}", ticket_id));
        let response = self.client.get(&path).await?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(ConnectorError::NotFound(format!(
                "Issue {} not found",
                ticket_id
            )));
        }

        if !response.status().is_success() {
            return Err(ConnectorError::RequestFailed(format!(
                "Failed to get issue: {}",
                response.status()
            )));
        }

        let issue: JiraIssue = response
            .json()
            .await
            .map_err(|e| ConnectorError::InvalidResponse(e.to_string()))?;

        Ok(self.parse_issue(issue))
    }

    #[instrument(skip(self, update), fields(ticket_id = %ticket_id))]
    async fn update_ticket(
        &self,
        ticket_id: &str,
        update: UpdateTicketRequest,
    ) -> ConnectorResult<Ticket> {
        let mut fields: HashMap<String, serde_json::Value> = HashMap::new();

        if let Some(title) = update.title {
            fields.insert("summary".to_string(), serde_json::json!(title));
        }

        if let Some(description) = update.description {
            if self.config.is_server {
                fields.insert("description".to_string(), serde_json::json!(description));
            } else {
                fields.insert(
                    "description".to_string(),
                    serde_json::json!(JiraDescription::text(&description)),
                );
            }
        }

        if let Some(priority) = update.priority {
            fields.insert(
                "priority".to_string(),
                serde_json::json!({"name": self.map_priority(priority)}),
            );
        }

        if let Some(assignee) = update.assignee {
            if self.config.is_server {
                fields.insert("assignee".to_string(), serde_json::json!({"name": assignee}));
            } else {
                fields.insert(
                    "assignee".to_string(),
                    serde_json::json!({"accountId": assignee}),
                );
            }
        }

        // Handle labels
        if !update.add_labels.is_empty() || !update.remove_labels.is_empty() {
            let current = self.get_ticket(ticket_id).await?;
            let mut labels: Vec<String> = current
                .labels
                .into_iter()
                .filter(|l| !update.remove_labels.contains(l))
                .collect();
            for label in update.add_labels {
                if !labels.contains(&label) {
                    labels.push(label);
                }
            }
            fields.insert("labels".to_string(), serde_json::json!(labels));
        }

        if !fields.is_empty() {
            let update_request = serde_json::json!({ "fields": fields });
            let path = self.api_path(&format!("/issue/{}", ticket_id));

            let response = self.client.put(&path, &update_request).await?;

            if !response.status().is_success() {
                let error_text = response.text().await.unwrap_or_default();
                return Err(ConnectorError::RequestFailed(format!(
                    "Failed to update issue: {}",
                    error_text
                )));
            }
        }

        // Handle status transition if specified
        if let Some(status) = update.status {
            self.transition_issue(ticket_id, &status).await?;
        }

        info!("Updated Jira issue: {}", ticket_id);
        self.get_ticket(ticket_id).await
    }

    #[instrument(skip(self, comment), fields(ticket_id = %ticket_id))]
    async fn add_comment(&self, ticket_id: &str, comment: &str) -> ConnectorResult<()> {
        let body = if self.config.is_server {
            serde_json::json!({ "body": comment })
        } else {
            serde_json::json!({ "body": JiraDescription::text(comment) })
        };

        let path = self.api_path(&format!("/issue/{}/comment", ticket_id));
        let response = self.client.post(&path, &body).await?;

        if !response.status().is_success() {
            let error = response.text().await.unwrap_or_default();
            return Err(ConnectorError::RequestFailed(format!(
                "Failed to add comment: {}",
                error
            )));
        }

        debug!("Added comment to issue {}", ticket_id);
        Ok(())
    }

    #[instrument(skip(self), fields(query = %query))]
    async fn search_tickets(&self, query: &str, limit: usize) -> ConnectorResult<Vec<Ticket>> {
        // Escape special JQL characters in the query
        let escaped_query = query.replace("\"", "\\\"");
        let jql = format!(
            "project = {} AND (summary ~ \"{}\" OR description ~ \"{}\")",
            self.config.project_key, escaped_query, escaped_query
        );

        self.search_jql(&jql, limit).await
    }

    async fn get_statuses(&self) -> ConnectorResult<Vec<TicketStatus>> {
        let path = self.api_path(&format!("/project/{}/statuses", self.config.project_key));
        let response = self.client.get(&path).await?;

        if !response.status().is_success() {
            return Err(ConnectorError::RequestFailed(format!(
                "Failed to get statuses: {}",
                response.status()
            )));
        }

        let issue_types: Vec<JiraIssueTypeStatuses> = response
            .json()
            .await
            .map_err(|e| ConnectorError::InvalidResponse(e.to_string()))?;

        // Flatten and deduplicate statuses across issue types
        let mut statuses: Vec<TicketStatus> = Vec::new();
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

        for issue_type in issue_types {
            for status in issue_type.statuses {
                if seen.insert(status.id.clone()) {
                    statuses.push(TicketStatus {
                        id: status.id,
                        name: status.name,
                        category: status.status_category.name,
                    });
                }
            }
        }

        Ok(statuses)
    }
}

// Jira API types

#[derive(Debug, Deserialize)]
struct JiraIssue {
    id: String,
    key: String,
    fields: JiraFields,
}

#[derive(Debug, Deserialize)]
struct JiraFields {
    summary: String,
    description: Option<serde_json::Value>,
    status: JiraStatus,
    priority: JiraPriority,
    assignee: Option<JiraUser>,
    reporter: Option<JiraUser>,
    labels: Vec<String>,
    created: DateTime<Utc>,
    updated: DateTime<Utc>,
    #[serde(flatten)]
    custom_fields: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct JiraStatus {
    name: String,
}

#[derive(Debug, Deserialize)]
struct JiraPriority {
    name: String,
}

#[derive(Debug, Deserialize)]
struct JiraUser {
    #[serde(rename = "displayName")]
    display_name: String,
}

#[derive(Debug, Deserialize)]
struct JiraCreateResponse {
    id: String,
    key: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct JiraDescription {
    #[serde(rename = "type")]
    doc_type: String,
    version: u32,
    content: Vec<JiraContent>,
}

impl JiraDescription {
    fn text(text: &str) -> Self {
        // Split text into paragraphs
        let paragraphs: Vec<JiraContent> = text
            .split("\n\n")
            .filter(|p| !p.is_empty())
            .map(|paragraph| JiraContent {
                content_type: "paragraph".to_string(),
                content: vec![JiraTextContent {
                    text_type: "text".to_string(),
                    text: paragraph.to_string(),
                }],
            })
            .collect();

        Self {
            doc_type: "doc".to_string(),
            version: 1,
            content: if paragraphs.is_empty() {
                vec![JiraContent {
                    content_type: "paragraph".to_string(),
                    content: vec![JiraTextContent {
                        text_type: "text".to_string(),
                        text: text.to_string(),
                    }],
                }]
            } else {
                paragraphs
            },
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct JiraContent {
    #[serde(rename = "type")]
    content_type: String,
    content: Vec<JiraTextContent>,
}

#[derive(Debug, Serialize, Deserialize)]
struct JiraTextContent {
    #[serde(rename = "type")]
    text_type: String,
    text: String,
}

#[derive(Debug, Serialize)]
struct JiraSearchRequest {
    jql: String,
    #[serde(rename = "maxResults")]
    max_results: u32,
    fields: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct JiraSearchResponse {
    issues: Vec<JiraIssue>,
}

#[derive(Debug, Deserialize)]
struct JiraIssueTypeStatuses {
    statuses: Vec<JiraStatusDetail>,
}

#[derive(Debug, Deserialize)]
struct JiraStatusDetail {
    id: String,
    name: String,
    #[serde(rename = "statusCategory")]
    status_category: JiraStatusCategory,
}

#[derive(Debug, Deserialize)]
struct JiraStatusCategory {
    name: String,
}

#[derive(Debug, Deserialize)]
struct JiraTransitionsResponse {
    transitions: Vec<JiraTransition>,
}

#[derive(Debug, Deserialize)]
struct JiraTransition {
    id: String,
    to: JiraStatus,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::AuthConfig;

    fn create_test_config() -> JiraConfig {
        JiraConfig {
            connector: ConnectorConfig {
                name: "jira-test".to_string(),
                base_url: "https://example.atlassian.net".to_string(),
                auth: AuthConfig::Basic {
                    username: "test@example.com".to_string(),
                    password: "api-token".to_string(),
                },
                timeout_secs: 30,
                max_retries: 3,
                verify_tls: true,
                headers: HashMap::new(),
            },
            project_key: "SEC".to_string(),
            default_issue_type: "Incident".to_string(),
            field_mappings: HashMap::new(),
            priority_mappings: HashMap::new(),
            is_server: false,
            default_component: Some("Security".to_string()),
            security_level: None,
        }
    }

    #[test]
    fn test_priority_mapping() {
        let config = create_test_config();
        let connector = JiraConnector::new(config).unwrap();

        assert_eq!(connector.map_priority(TicketPriority::Lowest), "Lowest");
        assert_eq!(connector.map_priority(TicketPriority::Low), "Low");
        assert_eq!(connector.map_priority(TicketPriority::Medium), "Medium");
        assert_eq!(connector.map_priority(TicketPriority::High), "High");
        assert_eq!(connector.map_priority(TicketPriority::Highest), "Highest");
    }

    #[test]
    fn test_priority_parsing() {
        let config = create_test_config();
        let connector = JiraConnector::new(config).unwrap();

        assert_eq!(connector.parse_priority("Lowest"), TicketPriority::Lowest);
        assert_eq!(connector.parse_priority("trivial"), TicketPriority::Lowest);
        assert_eq!(connector.parse_priority("Minor"), TicketPriority::Low);
        assert_eq!(connector.parse_priority("Medium"), TicketPriority::Medium);
        assert_eq!(connector.parse_priority("Major"), TicketPriority::High);
        assert_eq!(connector.parse_priority("Critical"), TicketPriority::Highest);
        assert_eq!(connector.parse_priority("Blocker"), TicketPriority::Highest);
    }

    #[test]
    fn test_jira_description_formatting() {
        let desc = JiraDescription::text("First paragraph\n\nSecond paragraph");
        assert_eq!(desc.content.len(), 2);
        assert_eq!(desc.content[0].content[0].text, "First paragraph");
        assert_eq!(desc.content[1].content[0].text, "Second paragraph");
    }

    #[test]
    fn test_api_path() {
        let mut config = create_test_config();
        let connector = JiraConnector::new(config.clone()).unwrap();
        assert_eq!(connector.api_path("/issue"), "/rest/api/3/issue");

        config.is_server = true;
        let connector = JiraConnector::new(config).unwrap();
        assert_eq!(connector.api_path("/issue"), "/rest/api/2/issue");
    }

    #[test]
    fn test_custom_priority_mappings() {
        let mut config = create_test_config();
        config.priority_mappings.insert("highest".to_string(), "P1".to_string());
        config.priority_mappings.insert("high".to_string(), "P2".to_string());

        let connector = JiraConnector::new(config).unwrap();
        assert_eq!(connector.map_priority(TicketPriority::Highest), "P1");
        assert_eq!(connector.map_priority(TicketPriority::High), "P2");
        assert_eq!(connector.map_priority(TicketPriority::Medium), "Medium"); // No mapping
    }
}
