//! Askama template definitions for the web dashboard.

use askama::Template;
use uuid::Uuid;

// ============================================
// User Info (for navigation display)
// ============================================

/// User information for template display.
#[derive(Clone)]
pub struct CurrentUserInfo {
    pub username: String,
    pub display_name: Option<String>,
    pub role: String,
}

// ============================================
// Dashboard
// ============================================

#[derive(Template)]
#[template(path = "dashboard.html")]
pub struct DashboardTemplate {
    pub active_nav: String,
    pub critical_count: u32,
    pub open_count: u32,
    pub approval_count: u32,
    pub system_healthy: bool,
    pub current_user: Option<CurrentUserInfo>,
    pub metrics: DashboardMetrics,
    pub recent_incidents: Vec<IncidentRow>,
}

#[derive(Clone)]
pub struct DashboardMetrics {
    pub critical_count: u32,
    pub open_count: u32,
    pub high_count: u32,
    pub medium_count: u32,
    pub low_count: u32,
    pub avg_response_time: String,
    pub response_time_trend: i32,
    pub auto_resolved_pct: u32,
    pub auto_resolved_trend: i32,
}

// ============================================
// Incidents List
// ============================================

#[derive(Template)]
#[template(path = "incidents/list.html")]
pub struct IncidentsListTemplate {
    pub active_nav: String,
    pub critical_count: u32,
    pub open_count: u32,
    pub approval_count: u32,
    pub system_healthy: bool,
    pub current_user: Option<CurrentUserInfo>,
    pub incidents: Vec<IncidentRow>,
    pub total_count: u32,
    pub severity_filter: String,
    pub status_filter: String,
    pub query: String,
    pub page: u32,
    pub total_pages: u32,
}

#[derive(Clone)]
pub struct IncidentRow {
    pub id: Uuid,
    pub title: String,
    pub severity: String,
    pub source: String,
    pub hostname: Option<String>,
    pub username: Option<String>,
    pub time_ago: String,
}

// ============================================
// Incident Detail
// ============================================

#[derive(Template)]
#[template(path = "incidents/detail.html")]
pub struct IncidentDetailTemplate {
    pub active_nav: String,
    pub critical_count: u32,
    pub open_count: u32,
    pub approval_count: u32,
    pub system_healthy: bool,
    pub current_user: Option<CurrentUserInfo>,
    pub incident: IncidentDetail,
}

pub struct IncidentDetail {
    pub id: Uuid,
    pub title: String,
    pub severity: String,
    pub status: String,
    pub source: String,
    pub created_at: String,
    pub alert_data: String,
    pub analysis: Option<AnalysisData>,
    pub enrichments: Vec<EnrichmentData>,
    pub iocs: Vec<IoCData>,
    pub proposed_actions: Vec<ProposedActionData>,
    pub audit_log: Vec<AuditEntry>,
}

pub struct AnalysisData {
    pub verdict: String,
    pub confidence: u32,
    pub risk_score: u32,
    pub summary: String,
    pub reasoning: Option<String>,
    pub mitre_techniques: Vec<MitreTechnique>,
}

pub struct MitreTechnique {
    pub id: String,
    pub name: String,
}

pub struct EnrichmentData {
    pub source: String,
    pub indicator_type: String,
    pub indicator: String,
    pub threat_level: String,
    pub details: Option<String>,
}

pub struct IoCData {
    pub ioc_type: String,
    pub value: String,
    pub threat_level: String,
}

pub struct ProposedActionData {
    pub id: Uuid,
    pub action_type: String,
    pub description: String,
    pub target: Option<String>,
    pub status: String,
}

pub struct AuditEntry {
    pub timestamp: String,
    pub action: String,
    pub actor: String,
    pub details: Option<String>,
}

// ============================================
// Approvals
// ============================================

#[derive(Template)]
#[template(path = "approvals.html")]
pub struct ApprovalsTemplate {
    pub active_nav: String,
    pub critical_count: u32,
    pub open_count: u32,
    pub approval_count: u32,
    pub system_healthy: bool,
    pub current_user: Option<CurrentUserInfo>,
    pub pending_actions: Vec<PendingAction>,
    pub recent_approvals: Vec<RecentApproval>,
}

pub struct PendingAction {
    pub id: Uuid,
    pub incident_id: Uuid,
    pub incident_title: String,
    pub action_type: String,
    pub description: String,
    pub target: Option<String>,
    pub risk_level: String,
    pub proposed_at: String,
    pub proposed_by: String,
}

#[allow(dead_code)]
pub struct RecentApproval {
    pub id: Uuid,
    pub incident_id: Uuid,
    pub incident_title: String,
    pub action_type: String,
    pub approved: bool,
    pub processed_at: String,
    pub processed_by: String,
}

// ============================================
// Playbooks
// ============================================

#[derive(Template)]
#[template(path = "playbooks.html")]
pub struct PlaybooksTemplate {
    pub active_nav: String,
    pub critical_count: u32,
    pub open_count: u32,
    pub approval_count: u32,
    pub system_healthy: bool,
    pub current_user: Option<CurrentUserInfo>,
    pub playbooks: Vec<PlaybookData>,
}

pub struct PlaybookData {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub enabled: bool,
    pub trigger_count: u32,
    pub step_count: u32,
    pub execution_count: u32,
}

#[derive(Template)]
#[template(path = "playbooks/detail.html")]
pub struct PlaybookDetailTemplate {
    pub active_nav: String,
    pub critical_count: u32,
    pub open_count: u32,
    pub approval_count: u32,
    pub system_healthy: bool,
    pub current_user: Option<CurrentUserInfo>,
    pub playbook: PlaybookDetailData,
}

pub struct PlaybookDetailData {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub trigger_type: String,
    pub trigger_condition: Option<String>,
    pub enabled: bool,
    pub trigger_count: u32,
    pub step_count: u32,
    pub execution_count: u32,
    pub stages: Vec<PlaybookStageData>,
    pub created_at: String,
    pub updated_at: String,
}

pub struct PlaybookStageData {
    pub name: String,
    pub description: Option<String>,
    pub parallel: bool,
    pub steps: Vec<PlaybookStepData>,
}

pub struct PlaybookStepData {
    pub action: String,
    pub parameters: Option<String>,
    pub requires_approval: bool,
}

// ============================================
// Settings
// ============================================

#[derive(Template)]
#[template(path = "settings.html")]
pub struct SettingsTemplate {
    pub active_nav: String,
    pub critical_count: u32,
    pub open_count: u32,
    pub approval_count: u32,
    pub system_healthy: bool,
    pub current_user: Option<CurrentUserInfo>,
    pub tab: String,
    pub settings: SettingsData,
    pub connectors: Vec<ConnectorData>,
    pub policies: Vec<PolicyData>,
    pub rate_limits: RateLimitsData,
    pub notification_channels: Vec<NotificationChannel>,
}

pub struct SettingsData {
    pub org_name: String,
    pub timezone: String,
    pub mode: String,
}

pub struct ConnectorData {
    pub id: Uuid,
    pub name: String,
    pub connector_type: String,
    pub status: String,
    pub last_check: Option<String>,
}

#[allow(dead_code)]
pub struct PolicyData {
    pub id: Uuid,
    pub name: String,
    pub condition: String,
    pub requires: String,
    pub enabled: bool,
}

pub struct RateLimitsData {
    pub isolate_host_hour: u32,
    pub disable_user_hour: u32,
    pub block_ip_hour: u32,
}

pub struct NotificationChannel {
    pub id: Uuid,
    pub name: String,
    pub channel_type: String,
    pub events: Vec<String>,
    pub enabled: bool,
}

// ============================================
// Partials (for HTMX)
// ============================================

#[derive(Template)]
#[template(path = "partials/kpis.html")]
pub struct KpisPartialTemplate {
    pub metrics: DashboardMetrics,
}

/// Template for rendering a list of incidents (used by HTMX partials).
#[derive(Template)]
#[template(
    source = r#"{% for incident in incidents %}
<li class="incident-item{% if incident.severity == "critical" %} critical{% endif %}"
    hx-get="/incidents/{{ incident.id }}"
    hx-push-url="true"
    hx-target="body">
  <div class="severity-dot {{ incident.severity }}"></div>
  <div class="incident-info">
    <div class="incident-title">{{ incident.title }}</div>
    <div class="incident-meta">
      {% if let Some(hostname) = incident.hostname %}{{ hostname }} &bull; {% endif %}
      {% if let Some(username) = incident.username %}{{ username }} &bull; {% endif %}
      {{ incident.source }}
    </div>
  </div>
  <div class="incident-time">{{ incident.time_ago }}</div>
  <div class="incident-actions">
    <button class="btn btn-primary"
            hx-get="/incidents/{{ incident.id }}"
            hx-push-url="true"
            hx-target="body"
            onclick="event.stopPropagation()">Investigate</button>
    <button class="btn btn-ghost"
            hx-post="/api/incidents/{{ incident.id }}/dismiss"
            hx-swap="outerHTML"
            hx-target="closest .incident-item"
            onclick="event.stopPropagation()">Dismiss</button>
  </div>
</li>
{% endfor %}
{% if incidents.is_empty() %}
<li class="empty-state">
  <svg class="empty-state-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
    <path d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
  </svg>
  <div class="empty-state-title">No incidents found</div>
  <div class="empty-state-text">Try adjusting your filters.</div>
</li>
{% endif %}"#,
    ext = "html"
)]
pub struct IncidentsPartialTemplate {
    pub incidents: Vec<IncidentRow>,
}

// ============================================
// Modal Partials
// ============================================

#[derive(Template)]
#[template(path = "partials/modal_add_playbook.html")]
pub struct AddPlaybookModalTemplate;

#[derive(Template)]
#[template(path = "partials/modal_add_connector.html")]
pub struct AddConnectorModalTemplate;

#[derive(Template)]
#[template(path = "partials/modal_edit_connector.html")]
pub struct EditConnectorModalTemplate {
    pub connector: EditConnectorData,
}

#[allow(dead_code)]
pub struct EditConnectorData {
    pub id: Uuid,
    pub name: String,
    pub connector_type: String,
    pub config: serde_json::Value,
    pub enabled: bool,
}

/// Partial template for connectors grid.
#[derive(Template)]
#[template(path = "partials/connectors_grid.html")]
pub struct ConnectorsPartialTemplate {
    pub connectors: Vec<ConnectorData>,
}

#[derive(Template)]
#[template(path = "partials/modal_add_policy.html")]
pub struct AddPolicyModalTemplate;

#[derive(Template)]
#[template(path = "partials/modal_edit_policy.html")]
pub struct EditPolicyModalTemplate {
    pub policy: EditPolicyData,
}

pub struct EditPolicyData {
    pub id: Uuid,
    pub name: String,
    pub condition: String,
    pub requires: String,
    pub enabled: bool,
}

/// Partial template for policies table.
#[derive(Template)]
#[template(path = "partials/policies_table.html")]
pub struct PoliciesPartialTemplate {
    pub policies: Vec<PolicyData>,
}

#[derive(Template)]
#[template(path = "partials/modal_add_notification.html")]
pub struct AddNotificationModalTemplate;

#[derive(Template)]
#[template(path = "partials/modal_edit_notification.html")]
pub struct EditNotificationModalTemplate {
    pub channel: EditNotificationChannel,
}

#[allow(dead_code)]
pub struct EditNotificationChannel {
    pub id: Uuid,
    pub name: String,
    pub channel_type: String,
    pub config: serde_json::Value,
    pub events: Vec<String>,
    pub enabled: bool,
    // Pre-computed event flags for template use
    pub has_critical_incident: bool,
    pub has_approval_needed: bool,
    pub has_action_executed: bool,
    pub has_playbook_failed: bool,
    pub has_connector_error: bool,
    pub has_system_health: bool,
    // Pre-computed config values for template use
    pub webhook_url: String,
    pub channel_name: String,
    pub recipients: String,
    pub smtp_host: String,
    pub smtp_port: String,
    pub integration_key: String,
    pub pd_severity: String,
    pub auth_header: String,
}

impl EditNotificationChannel {
    /// Creates an EditNotificationChannel from a notification channel.
    pub fn from_channel(
        id: Uuid,
        name: String,
        channel_type: String,
        config: serde_json::Value,
        events: Vec<String>,
        enabled: bool,
    ) -> Self {
        let get_config = |key: &str| -> String {
            config
                .get(key)
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string()
        };

        Self {
            id,
            name,
            channel_type,
            enabled,
            has_critical_incident: events.iter().any(|e| e == "critical_incident"),
            has_approval_needed: events.iter().any(|e| e == "approval_needed"),
            has_action_executed: events.iter().any(|e| e == "action_executed"),
            has_playbook_failed: events.iter().any(|e| e == "playbook_failed"),
            has_connector_error: events.iter().any(|e| e == "connector_error"),
            has_system_health: events.iter().any(|e| e == "system_health"),
            webhook_url: get_config("webhook_url"),
            channel_name: get_config("channel"),
            recipients: get_config("recipients"),
            smtp_host: get_config("smtp_host"),
            smtp_port: get_config("smtp_port"),
            integration_key: get_config("integration_key"),
            pd_severity: get_config("severity"),
            auth_header: get_config("auth_header"),
            config,
            events,
        }
    }
}

/// Partial template for notifications table.
#[derive(Template)]
#[template(path = "partials/notifications_table.html")]
pub struct NotificationsPartialTemplate {
    pub notification_channels: Vec<NotificationChannel>,
}
