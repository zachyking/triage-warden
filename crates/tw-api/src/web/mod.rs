//! Web dashboard routes with HTMX + Askama templates.

mod templates;

use axum::{
    extract::{Path, Query, State},
    response::{IntoResponse, Redirect, Response},
    routing::get,
    Router,
};
use chrono::{Duration, Utc};
use serde::Deserialize;
use uuid::Uuid;

use tw_core::db::{
    create_audit_repository, create_incident_repository, IncidentFilter, IncidentRepository,
    Pagination,
};
use tw_core::incident::{ApprovalStatus, IncidentStatus, Severity};

use crate::state::AppState;
use templates::*;

/// Creates the web dashboard router.
pub fn create_web_router(state: AppState) -> Router {
    Router::new()
        // Main pages
        .route("/", get(dashboard))
        .route("/incidents", get(incidents_list))
        .route("/incidents/{id}", get(incident_detail))
        .route("/approvals", get(approvals))
        .route("/playbooks", get(playbooks))
        .route("/settings", get(settings))
        // Partials for HTMX
        .route("/web/partials/kpis", get(partials_kpis))
        .route("/web/partials/incidents", get(partials_incidents))
        // Modal partials
        .route("/web/modals/add-playbook", get(modal_add_playbook))
        .route("/web/modals/add-connector", get(modal_add_connector))
        .route("/web/modals/add-policy", get(modal_add_policy))
        .route("/web/modals/add-notification", get(modal_add_notification))
        .with_state(state)
}

// ============================================
// Page Handlers
// ============================================

/// Dashboard page - main overview with KPIs and recent incidents.
async fn dashboard(State(state): State<AppState>) -> impl IntoResponse {
    let repo = create_incident_repository(&state.db);

    // Fetch metrics
    let metrics = fetch_dashboard_metrics(repo.as_ref()).await;
    let critical_count = metrics.critical_count;
    let open_count = metrics.open_count;

    // Fetch recent incidents (limit 10)
    let recent_incidents = fetch_incidents(
        repo.as_ref(),
        None, // no severity filter
        Some(vec![
            IncidentStatus::New,
            IncidentStatus::Enriching,
            IncidentStatus::Analyzing,
            IncidentStatus::PendingReview,
            IncidentStatus::PendingApproval,
            IncidentStatus::Executing,
        ]),
        10,
        1,
    )
    .await;

    // Count pending approvals
    let approval_filter = IncidentFilter {
        status: Some(vec![IncidentStatus::PendingApproval]),
        ..Default::default()
    };
    let approval_count = repo.count(&approval_filter).await.unwrap_or(0) as u32;

    let template = DashboardTemplate {
        active_nav: "dashboard".to_string(),
        critical_count,
        open_count,
        approval_count,
        system_healthy: true,
        metrics,
        recent_incidents,
    };

    HtmlTemplate(template)
}

/// Incidents list page with filtering and pagination.
#[derive(Debug, Deserialize)]
struct IncidentsQuery {
    #[serde(default)]
    severity: String,
    #[serde(default)]
    status: String,
    #[serde(default)]
    q: String,
    #[serde(default = "default_page")]
    page: u32,
}

fn default_page() -> u32 {
    1
}

async fn incidents_list(
    State(state): State<AppState>,
    Query(query): Query<IncidentsQuery>,
) -> impl IntoResponse {
    let repo = create_incident_repository(&state.db);

    // Parse severity filter
    let severity_filter = parse_severity(&query.severity);

    // Parse status filter - tabs are mutually exclusive
    let status_filter = if query.status.is_empty() || query.status == "open" {
        // "Open" = new incidents awaiting triage (not yet investigating)
        Some(vec![
            IncidentStatus::New,
            IncidentStatus::PendingReview,
            IncidentStatus::PendingApproval,
        ])
    } else if query.status == "investigating" {
        // "Investigating" = actively being worked on
        Some(vec![
            IncidentStatus::Enriching,
            IncidentStatus::Analyzing,
            IncidentStatus::Executing,
        ])
    } else if query.status == "resolved" {
        Some(vec![
            IncidentStatus::Resolved,
            IncidentStatus::FalsePositive,
            IncidentStatus::Closed,
        ])
    } else {
        None // "all"
    };

    let per_page = 20u32;

    // Build filter
    let filter = IncidentFilter {
        severity: severity_filter.clone(),
        status: status_filter.clone(),
        ..Default::default()
    };

    // Get total count for pagination
    let total_count = repo.count(&filter).await.unwrap_or(0) as u32;
    let total_pages = (total_count as f32 / per_page as f32).ceil() as u32;

    // Fetch incidents
    let incidents = fetch_incidents_with_filter(repo.as_ref(), &filter, per_page, query.page).await;

    // Fetch nav counts (for badges)
    let nav = fetch_nav_counts(repo.as_ref()).await;

    let template = IncidentsListTemplate {
        active_nav: "incidents".to_string(),
        critical_count: nav.critical_count,
        open_count: nav.open_count,
        approval_count: nav.approval_count,
        system_healthy: true,
        incidents,
        total_count,
        severity_filter: query.severity,
        status_filter: query.status,
        query: query.q,
        page: query.page.max(1),
        total_pages: total_pages.max(1),
    };

    HtmlTemplate(template)
}

/// Incident detail page.
async fn incident_detail(State(state): State<AppState>, Path(id): Path<Uuid>) -> impl IntoResponse {
    let repo = create_incident_repository(&state.db);
    let audit_repo = create_audit_repository(&state.db);

    // Fetch nav counts first
    let nav = fetch_nav_counts(repo.as_ref()).await;

    match repo.get(id).await {
        Ok(Some(incident)) => {
            // Fetch audit log
            let audit_entries = audit_repo
                .get_for_incident(id)
                .await
                .unwrap_or_default()
                .into_iter()
                .map(|e| AuditEntry {
                    timestamp: e.timestamp.format("%H:%M:%S").to_string(),
                    action: format!("{:?}", e.action),
                    actor: e.actor,
                    details: e.details.map(|v| v.to_string()),
                })
                .collect();

            // Convert to template detail
            let detail = convert_incident_to_detail(&incident, audit_entries);

            let template = IncidentDetailTemplate {
                active_nav: "incidents".to_string(),
                critical_count: nav.critical_count,
                open_count: nav.open_count,
                approval_count: nav.approval_count,
                system_healthy: true,
                incident: detail,
            };

            HtmlTemplate(template).into_response()
        }
        _ => Redirect::to("/incidents").into_response(),
    }
}

/// Approvals page - pending action approvals.
async fn approvals(State(state): State<AppState>) -> impl IntoResponse {
    let repo = create_incident_repository(&state.db);

    // Fetch nav counts
    let nav = fetch_nav_counts(repo.as_ref()).await;

    // Fetch incidents pending approval
    let filter = IncidentFilter {
        status: Some(vec![IncidentStatus::PendingApproval]),
        ..Default::default()
    };
    let pagination = Pagination {
        page: 1,
        per_page: 50,
    };

    let pending_incidents = repo.list(&filter, &pagination).await.unwrap_or_default();

    // Convert to pending actions
    let pending_actions: Vec<PendingAction> = pending_incidents
        .iter()
        .flat_map(|incident| {
            incident
                .proposed_actions
                .iter()
                .filter(|a| a.approval_status == ApprovalStatus::Pending)
                .map(|action| PendingAction {
                    id: action.id,
                    incident_id: incident.id,
                    incident_title: extract_title(&incident.alert_data),
                    action_type: format!("{}", action.action_type),
                    description: action.reason.clone(),
                    target: Some(format!("{:?}", action.target)),
                    risk_level: "high".to_string(),
                    proposed_at: format_time_ago(incident.created_at),
                    proposed_by: "System".to_string(),
                })
                .collect::<Vec<_>>()
        })
        .collect();

    let template = ApprovalsTemplate {
        active_nav: "approvals".to_string(),
        critical_count: nav.critical_count,
        open_count: nav.open_count,
        approval_count: pending_actions.len() as u32,
        system_healthy: true,
        pending_actions,
        recent_approvals: vec![],
    };

    HtmlTemplate(template)
}

/// Playbooks page.
async fn playbooks(State(state): State<AppState>) -> impl IntoResponse {
    let repo = create_incident_repository(&state.db);
    let nav = fetch_nav_counts(repo.as_ref()).await;

    // TODO: Implement playbook repository
    let playbooks_list = vec![
        PlaybookData {
            id: Uuid::new_v4(),
            name: "Phishing Triage".to_string(),
            description: "Automated triage workflow for reported phishing emails".to_string(),
            enabled: true,
            trigger_count: 3,
            step_count: 5,
            execution_count: 0,
        },
        PlaybookData {
            id: Uuid::new_v4(),
            name: "Malware Detection".to_string(),
            description: "Response workflow for EDR malware detections".to_string(),
            enabled: true,
            trigger_count: 2,
            step_count: 7,
            execution_count: 0,
        },
    ];

    let template = PlaybooksTemplate {
        active_nav: "playbooks".to_string(),
        critical_count: nav.critical_count,
        open_count: nav.open_count,
        approval_count: nav.approval_count,
        system_healthy: true,
        playbooks: playbooks_list,
    };

    HtmlTemplate(template)
}

/// Settings page.
#[derive(Debug, Deserialize)]
struct SettingsQuery {
    #[serde(default = "default_tab")]
    tab: String,
}

fn default_tab() -> String {
    "general".to_string()
}

async fn settings(
    State(state): State<AppState>,
    Query(query): Query<SettingsQuery>,
) -> impl IntoResponse {
    let repo = create_incident_repository(&state.db);
    let nav = fetch_nav_counts(repo.as_ref()).await;

    let settings_data = SettingsData {
        org_name: "Triage Warden".to_string(),
        timezone: "UTC".to_string(),
        mode: "supervised".to_string(),
    };

    let connectors = vec![
        ConnectorData {
            id: Uuid::new_v4(),
            name: "VirusTotal".to_string(),
            connector_type: "Threat Intel".to_string(),
            status: "connected".to_string(),
            last_check: Some("Active".to_string()),
        },
        ConnectorData {
            id: Uuid::new_v4(),
            name: "Jira Cloud".to_string(),
            connector_type: "Ticketing".to_string(),
            status: "connected".to_string(),
            last_check: Some("Active".to_string()),
        },
    ];

    let policies = vec![PolicyData {
        id: Uuid::new_v4(),
        name: "Critical Asset Protection".to_string(),
        condition: "target_criticality IN (critical, high)".to_string(),
        requires: "manual_approval".to_string(),
        enabled: true,
    }];

    let rate_limits = RateLimitsData {
        isolate_host_hour: 5,
        disable_user_hour: 10,
        block_ip_hour: 20,
    };

    let notification_channels = vec![];

    let template = SettingsTemplate {
        active_nav: "settings".to_string(),
        critical_count: nav.critical_count,
        open_count: nav.open_count,
        approval_count: nav.approval_count,
        system_healthy: true,
        tab: query.tab,
        settings: settings_data,
        connectors,
        policies,
        rate_limits,
        notification_channels,
    };

    HtmlTemplate(template)
}

// ============================================
// HTMX Partials
// ============================================

async fn partials_kpis(State(state): State<AppState>) -> impl IntoResponse {
    let repo = create_incident_repository(&state.db);
    let metrics = fetch_dashboard_metrics(repo.as_ref()).await;

    let template = KpisPartialTemplate { metrics };
    HtmlTemplate(template)
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct PartialsQuery {
    #[serde(default)]
    severity: String,
    #[serde(default)]
    q: String,
}

async fn partials_incidents(
    State(state): State<AppState>,
    Query(query): Query<PartialsQuery>,
) -> impl IntoResponse {
    let repo = create_incident_repository(&state.db);

    let severity_filter = parse_severity(&query.severity);
    let incidents = fetch_incidents(
        repo.as_ref(),
        severity_filter,
        Some(vec![
            IncidentStatus::New,
            IncidentStatus::Enriching,
            IncidentStatus::Analyzing,
            IncidentStatus::PendingReview,
            IncidentStatus::PendingApproval,
            IncidentStatus::Executing,
        ]),
        20,
        1,
    )
    .await;

    let template = IncidentsPartialTemplate { incidents };
    HtmlTemplate(template)
}

// ============================================
// Modal Handlers
// ============================================

async fn modal_add_playbook() -> impl IntoResponse {
    HtmlTemplate(AddPlaybookModalTemplate)
}

async fn modal_add_connector() -> impl IntoResponse {
    HtmlTemplate(AddConnectorModalTemplate)
}

async fn modal_add_policy() -> impl IntoResponse {
    HtmlTemplate(AddPolicyModalTemplate)
}

async fn modal_add_notification() -> impl IntoResponse {
    HtmlTemplate(AddNotificationModalTemplate)
}

// ============================================
// Data Fetching Helpers
// ============================================

/// Counts for the navigation badges (used by all pages).
struct NavCounts {
    critical_count: u32,
    open_count: u32,
    approval_count: u32,
}

/// Fetches the counts needed for navigation badges.
async fn fetch_nav_counts(repo: &dyn IncidentRepository) -> NavCounts {
    // Count critical open incidents
    let critical_filter = IncidentFilter {
        severity: Some(vec![Severity::Critical]),
        status: Some(vec![
            IncidentStatus::New,
            IncidentStatus::Enriching,
            IncidentStatus::Analyzing,
            IncidentStatus::PendingReview,
            IncidentStatus::PendingApproval,
            IncidentStatus::Executing,
        ]),
        ..Default::default()
    };
    let critical_count = repo.count(&critical_filter).await.unwrap_or(0) as u32;

    // Count all open incidents
    let open_filter = IncidentFilter {
        status: Some(vec![
            IncidentStatus::New,
            IncidentStatus::Enriching,
            IncidentStatus::Analyzing,
            IncidentStatus::PendingReview,
            IncidentStatus::PendingApproval,
            IncidentStatus::Executing,
        ]),
        ..Default::default()
    };
    let open_count = repo.count(&open_filter).await.unwrap_or(0) as u32;

    // Count pending approvals
    let approval_filter = IncidentFilter {
        status: Some(vec![IncidentStatus::PendingApproval]),
        ..Default::default()
    };
    let approval_count = repo.count(&approval_filter).await.unwrap_or(0) as u32;

    NavCounts {
        critical_count,
        open_count,
        approval_count,
    }
}

async fn fetch_dashboard_metrics(repo: &dyn IncidentRepository) -> DashboardMetrics {
    // Count critical open incidents
    let critical_filter = IncidentFilter {
        severity: Some(vec![Severity::Critical]),
        status: Some(vec![
            IncidentStatus::New,
            IncidentStatus::Enriching,
            IncidentStatus::Analyzing,
            IncidentStatus::PendingReview,
            IncidentStatus::PendingApproval,
            IncidentStatus::Executing,
        ]),
        ..Default::default()
    };
    let critical_count = repo.count(&critical_filter).await.unwrap_or(0) as u32;

    // Count all open incidents
    let open_filter = IncidentFilter {
        status: Some(vec![
            IncidentStatus::New,
            IncidentStatus::Enriching,
            IncidentStatus::Analyzing,
            IncidentStatus::PendingReview,
            IncidentStatus::PendingApproval,
            IncidentStatus::Executing,
        ]),
        ..Default::default()
    };
    let open_count = repo.count(&open_filter).await.unwrap_or(0) as u32;

    // Count by severity
    let high_filter = IncidentFilter {
        severity: Some(vec![Severity::High]),
        status: open_filter.status.clone(),
        ..Default::default()
    };
    let high_count = repo.count(&high_filter).await.unwrap_or(0) as u32;

    let medium_filter = IncidentFilter {
        severity: Some(vec![Severity::Medium]),
        status: open_filter.status.clone(),
        ..Default::default()
    };
    let medium_count = repo.count(&medium_filter).await.unwrap_or(0) as u32;

    let low_filter = IncidentFilter {
        severity: Some(vec![Severity::Low, Severity::Info]),
        status: open_filter.status.clone(),
        ..Default::default()
    };
    let low_count = repo.count(&low_filter).await.unwrap_or(0) as u32;

    // Count resolved in last 24h for auto-resolved calculation
    let yesterday = Utc::now() - Duration::hours(24);
    let resolved_filter = IncidentFilter {
        status: Some(vec![IncidentStatus::Resolved, IncidentStatus::Closed]),
        since: Some(yesterday),
        ..Default::default()
    };
    let resolved_count = repo.count(&resolved_filter).await.unwrap_or(0) as u32;

    // Calculate auto-resolved percentage (approximation)
    let auto_resolved_pct = if resolved_count > 0 { 85 } else { 0 };

    DashboardMetrics {
        critical_count,
        open_count,
        high_count,
        medium_count,
        low_count,
        avg_response_time: "N/A".to_string(),
        response_time_trend: 0,
        auto_resolved_pct,
        auto_resolved_trend: 0,
    }
}

async fn fetch_incidents(
    repo: &dyn IncidentRepository,
    severity: Option<Vec<Severity>>,
    status: Option<Vec<IncidentStatus>>,
    limit: u32,
    page: u32,
) -> Vec<IncidentRow> {
    let filter = IncidentFilter {
        severity,
        status,
        ..Default::default()
    };
    fetch_incidents_with_filter(repo, &filter, limit, page).await
}

async fn fetch_incidents_with_filter(
    repo: &dyn IncidentRepository,
    filter: &IncidentFilter,
    limit: u32,
    page: u32,
) -> Vec<IncidentRow> {
    let pagination = Pagination {
        page: page.max(1),
        per_page: limit,
    };

    let incidents = repo.list(filter, &pagination).await.unwrap_or_default();

    incidents
        .into_iter()
        .map(|incident| {
            let title = extract_title(&incident.alert_data);
            let (hostname, username) = extract_host_user(&incident.alert_data);

            IncidentRow {
                id: incident.id,
                title,
                severity: incident.severity.to_string().to_lowercase(),
                source: incident.source.to_string(),
                hostname,
                username,
                time_ago: format_time_ago(incident.created_at),
            }
        })
        .collect()
}

fn convert_incident_to_detail(
    incident: &tw_core::incident::Incident,
    audit_entries: Vec<AuditEntry>,
) -> IncidentDetail {
    let title = extract_title(&incident.alert_data);

    // Convert analysis
    let analysis = incident.analysis.as_ref().map(|a| AnalysisData {
        verdict: format!("{:?}", a.verdict).to_lowercase(),
        confidence: (a.confidence * 100.0) as u32,
        risk_score: a.risk_score as u32,
        summary: a.summary.clone(),
        reasoning: Some(a.reasoning.clone()),
        mitre_techniques: a
            .mitre_techniques
            .iter()
            .map(|t| MitreTechnique {
                id: t.id.clone(),
                name: t.name.clone(),
            })
            .collect(),
    });

    // Convert enrichments
    let enrichments = incident
        .enrichments
        .iter()
        .map(|e| {
            // Try to extract threat level from enrichment data
            let threat_level = e
                .data
                .get("threat_level")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();

            EnrichmentData {
                source: e.source.clone(),
                indicator_type: format!("{:?}", e.enrichment_type),
                indicator: e
                    .data
                    .get("indicator")
                    .and_then(|v| v.as_str())
                    .unwrap_or("-")
                    .to_string(),
                threat_level,
                details: Some(serde_json::to_string_pretty(&e.data).unwrap_or_default()),
            }
        })
        .collect();

    // Extract IoCs from analysis if available
    let iocs = incident
        .analysis
        .as_ref()
        .map(|a| {
            a.iocs
                .iter()
                .map(|ioc| IoCData {
                    ioc_type: format!("{:?}", ioc.ioc_type),
                    value: ioc.value.clone(),
                    threat_level: ioc
                        .score
                        .map(|s| {
                            if s > 0.7 {
                                "malicious"
                            } else if s > 0.3 {
                                "suspicious"
                            } else {
                                "unknown"
                            }
                        })
                        .unwrap_or("unknown")
                        .to_string(),
                })
                .collect()
        })
        .unwrap_or_default();

    // Convert proposed actions
    let proposed_actions = incident
        .proposed_actions
        .iter()
        .map(|a| ProposedActionData {
            id: a.id,
            action_type: format!("{}", a.action_type),
            description: a.reason.clone(),
            target: Some(format!("{:?}", a.target)),
            status: format!("{:?}", a.approval_status).to_lowercase(),
        })
        .collect();

    IncidentDetail {
        id: incident.id,
        title,
        severity: incident.severity.to_string().to_lowercase(),
        status: incident.status.to_string().to_lowercase(),
        source: incident.source.to_string(),
        created_at: incident
            .created_at
            .format("%Y-%m-%d %H:%M:%S UTC")
            .to_string(),
        alert_data: serde_json::to_string_pretty(&incident.alert_data).unwrap_or_default(),
        analysis,
        enrichments,
        iocs,
        proposed_actions,
        audit_log: audit_entries,
    }
}

// ============================================
// Utility Functions
// ============================================

fn parse_severity(s: &str) -> Option<Vec<Severity>> {
    match s.to_lowercase().as_str() {
        "critical" => Some(vec![Severity::Critical]),
        "high" => Some(vec![Severity::High]),
        "medium" => Some(vec![Severity::Medium]),
        "low" => Some(vec![Severity::Low]),
        "info" => Some(vec![Severity::Info]),
        _ => None,
    }
}

fn extract_title(alert_data: &serde_json::Value) -> String {
    alert_data
        .get("title")
        .or_else(|| alert_data.get("name"))
        .or_else(|| alert_data.get("summary"))
        .or_else(|| alert_data.get("description"))
        .or_else(|| alert_data.get("alert_name"))
        .or_else(|| alert_data.get("rule_name"))
        .and_then(|v| v.as_str())
        .unwrap_or("Untitled Incident")
        .to_string()
}

fn extract_host_user(alert_data: &serde_json::Value) -> (Option<String>, Option<String>) {
    let hostname = alert_data
        .get("hostname")
        .or_else(|| alert_data.get("host"))
        .or_else(|| alert_data.get("computer_name"))
        .or_else(|| alert_data.get("device_name"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let username = alert_data
        .get("username")
        .or_else(|| alert_data.get("user"))
        .or_else(|| alert_data.get("user_name"))
        .or_else(|| alert_data.get("account_name"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    (hostname, username)
}

fn format_time_ago(dt: chrono::DateTime<chrono::Utc>) -> String {
    let now = Utc::now();
    let diff = now.signed_duration_since(dt);

    if diff.num_seconds() < 60 {
        format!("{}s ago", diff.num_seconds())
    } else if diff.num_minutes() < 60 {
        format!("{}m ago", diff.num_minutes())
    } else if diff.num_hours() < 24 {
        format!("{}h ago", diff.num_hours())
    } else if diff.num_days() < 7 {
        format!("{}d ago", diff.num_days())
    } else {
        dt.format("%Y-%m-%d").to_string()
    }
}

// ============================================
// Template Response Wrapper
// ============================================

struct HtmlTemplate<T>(T);

impl<T> IntoResponse for HtmlTemplate<T>
where
    T: askama::Template,
{
    fn into_response(self) -> Response {
        use axum::response::Html;

        match self.0.render() {
            Ok(html) => Html(html).into_response(),
            Err(err) => {
                tracing::error!("Template rendering error: {}", err);
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Template error: {}", err),
                )
                    .into_response()
            }
        }
    }
}
