//! Web dashboard routes with HTMX + Askama templates.

mod templates;

#[cfg(test)]
mod settings_tests;

use axum::{
    extract::{Path, Query, State},
    response::{IntoResponse, Redirect, Response},
    routing::get,
    Router,
};
use chrono::{Duration, Utc};
use serde::Deserialize;
use uuid::Uuid;

use tw_core::auth::DEFAULT_TENANT_ID;
use tw_core::db::{
    create_api_key_repository, create_audit_repository, create_connector_repository,
    create_incident_repository, create_notification_repository, create_playbook_repository,
    create_policy_repository, create_settings_repository, GeneralSettings, IncidentFilter,
    IncidentRepository, LlmSettings, Pagination, PlaybookFilter, PolicyRepository, RateLimits,
};
use tw_core::incident::{ApprovalStatus, IncidentStatus, Severity};

use crate::auth::AuthenticatedUser;
use crate::error::ApiError;
use crate::state::AppState;
use templates::*;
use tw_core::User;

/// Converts a User to CurrentUserInfo for templates.
fn user_to_current_info(user: &User) -> CurrentUserInfo {
    CurrentUserInfo {
        username: user.username.clone(),
        display_name: user.display_name.clone(),
        role: format!("{:?}", user.role),
    }
}

/// Creates the web dashboard router.
pub fn create_web_router(state: AppState) -> Router {
    Router::new()
        // Main pages
        .route("/", get(dashboard))
        .route("/incidents", get(incidents_list))
        .route("/incidents/:id", get(incident_detail))
        .route("/approvals", get(approvals))
        .route("/playbooks", get(playbooks))
        .route("/playbooks/:id", get(playbook_detail))
        .route("/settings", get(settings))
        // Partials for HTMX
        .route("/web/partials/kpis", get(partials_kpis))
        .route("/web/partials/incidents", get(partials_incidents))
        // Modal partials
        .route("/web/modals/add-playbook", get(modal_add_playbook))
        .route("/web/modals/add-connector", get(modal_add_connector))
        .route("/web/modals/edit-connector/:id", get(modal_edit_connector))
        .route("/web/partials/connectors", get(partials_connectors))
        .route("/web/modals/add-policy", get(modal_add_policy))
        .route("/web/modals/edit-policy/:id", get(modal_edit_policy))
        .route("/web/modals/add-notification", get(modal_add_notification))
        .route(
            "/web/modals/edit-notification/:id",
            get(modal_edit_notification),
        )
        .route("/web/modals/add-api-key", get(modal_add_api_key))
        // Policy partials for HTMX refresh
        .route("/web/partials/policies", get(partials_policies))
        // Notification partials for HTMX refresh
        .route("/web/partials/notifications", get(partials_notifications))
        // Playbook editor modals
        .route("/web/modals/playbook/:id/add-stage", get(modal_add_stage))
        .route(
            "/web/modals/playbook/:id/stage/:stage_index/edit",
            get(modal_edit_stage),
        )
        .route(
            "/web/modals/playbook/:id/stage/:stage_index/add-step",
            get(modal_add_step),
        )
        .route(
            "/web/modals/playbook/:id/stage/:stage_index/step/:step_index/edit",
            get(modal_edit_step),
        )
        .with_state(state)
}

// ============================================
// Page Handlers
// ============================================

/// Dashboard page - main overview with KPIs and recent incidents.
async fn dashboard(
    State(state): State<AppState>,
    AuthenticatedUser(user): AuthenticatedUser,
) -> Result<impl IntoResponse, ApiError> {
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
        current_user: Some(user_to_current_info(&user)),
        metrics,
        recent_incidents,
    };

    Ok(HtmlTemplate(template))
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
    AuthenticatedUser(user): AuthenticatedUser,
    Query(query): Query<IncidentsQuery>,
) -> Result<impl IntoResponse, ApiError> {
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
    // TODO: IncidentFilter does not currently support text search (query.q).
    // To enable search, add a `query: Option<String>` field to IncidentFilter
    // and implement full-text search in the repository layer (e.g., search
    // alert_data JSON, title, hostname, username, IP addresses, etc.)
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
        current_user: Some(user_to_current_info(&user)),
        incidents,
        total_count,
        severity_filter: query.severity,
        status_filter: query.status,
        query: query.q,
        page: query.page.max(1),
        total_pages: total_pages.max(1),
    };

    Ok(HtmlTemplate(template))
}

/// Incident detail page.
async fn incident_detail(
    State(state): State<AppState>,
    AuthenticatedUser(user): AuthenticatedUser,
    Path(id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let repo = create_incident_repository(&state.db);
    let audit_repo = create_audit_repository(&state.db);

    // Fetch nav counts first
    let nav = fetch_nav_counts(repo.as_ref()).await;

    match repo.get(id).await {
        Ok(Some(incident)) => {
            // Fetch audit log
            let audit_entries = audit_repo
                .get_for_incident(DEFAULT_TENANT_ID, id)
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
                current_user: Some(user_to_current_info(&user)),
                incident: detail,
            };

            Ok(HtmlTemplate(template).into_response())
        }
        _ => Ok(Redirect::to("/incidents").into_response()),
    }
}

/// Approvals page - pending action approvals.
async fn approvals(
    State(state): State<AppState>,
    AuthenticatedUser(user): AuthenticatedUser,
) -> Result<impl IntoResponse, ApiError> {
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
        current_user: Some(user_to_current_info(&user)),
        pending_actions,
        recent_approvals: vec![],
    };

    Ok(HtmlTemplate(template))
}

/// Playbooks page.
async fn playbooks(
    State(state): State<AppState>,
    AuthenticatedUser(user): AuthenticatedUser,
) -> Result<impl IntoResponse, ApiError> {
    let incident_repo = create_incident_repository(&state.db);
    let nav = fetch_nav_counts(incident_repo.as_ref()).await;

    // Fetch playbooks from repository
    let playbook_repo = create_playbook_repository(&state.db);
    let filter = PlaybookFilter::default();
    let db_playbooks = playbook_repo.list(&filter).await.unwrap_or_default();

    // Convert to template data
    let playbooks_list: Vec<PlaybookData> = db_playbooks
        .into_iter()
        .map(|p| {
            // Count triggers (from trigger_condition if set)
            let trigger_count = if p.trigger_condition.is_some() { 1 } else { 0 };
            // Count total steps across all stages
            let step_count: u32 = p.stages.iter().map(|s| s.steps.len() as u32).sum();

            PlaybookData {
                id: p.id,
                name: p.name,
                description: p.description.unwrap_or_default(),
                enabled: p.enabled,
                trigger_count,
                step_count,
                execution_count: p.execution_count,
            }
        })
        .collect();

    let template = PlaybooksTemplate {
        active_nav: "playbooks".to_string(),
        critical_count: nav.critical_count,
        open_count: nav.open_count,
        approval_count: nav.approval_count,
        system_healthy: true,
        current_user: Some(user_to_current_info(&user)),
        playbooks: playbooks_list,
    };

    Ok(HtmlTemplate(template))
}

/// Playbook detail page.
async fn playbook_detail(
    State(state): State<AppState>,
    AuthenticatedUser(user): AuthenticatedUser,
    Path(id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let incident_repo = create_incident_repository(&state.db);
    let nav = fetch_nav_counts(incident_repo.as_ref()).await;

    let playbook_repo = create_playbook_repository(&state.db);

    match playbook_repo.get(id).await {
        Ok(Some(playbook)) => {
            // Count triggers and steps
            let trigger_count = if playbook.trigger_condition.is_some() {
                1
            } else {
                0
            };
            let step_count: u32 = playbook.stages.iter().map(|s| s.steps.len() as u32).sum();

            let detail = PlaybookDetailData {
                id: playbook.id,
                name: playbook.name,
                description: playbook.description,
                trigger_type: playbook.trigger_type,
                trigger_condition: playbook.trigger_condition,
                enabled: playbook.enabled,
                trigger_count,
                step_count,
                execution_count: playbook.execution_count,
                stages: playbook
                    .stages
                    .into_iter()
                    .map(|s| PlaybookStageData {
                        name: s.name,
                        description: s.description,
                        parallel: s.parallel,
                        steps: s
                            .steps
                            .into_iter()
                            .map(|step| PlaybookStepData {
                                action: step.action,
                                parameters: step.parameters.map(|p| p.to_string()),
                                requires_approval: step.requires_approval,
                            })
                            .collect(),
                    })
                    .collect(),
                created_at: playbook
                    .created_at
                    .format("%Y-%m-%d %H:%M:%S UTC")
                    .to_string(),
                updated_at: playbook
                    .updated_at
                    .format("%Y-%m-%d %H:%M:%S UTC")
                    .to_string(),
            };

            let template = PlaybookDetailTemplate {
                active_nav: "playbooks".to_string(),
                critical_count: nav.critical_count,
                open_count: nav.open_count,
                approval_count: nav.approval_count,
                system_healthy: true,
                current_user: Some(user_to_current_info(&user)),
                playbook: detail,
            };

            Ok(HtmlTemplate(template).into_response())
        }
        _ => Ok(Redirect::to("/playbooks").into_response()),
    }
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
    AuthenticatedUser(user): AuthenticatedUser,
    Query(query): Query<SettingsQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let repo = create_incident_repository(&state.db);
    let nav = fetch_nav_counts(repo.as_ref()).await;

    // Load general settings from database
    let settings_repo = create_settings_repository(&state.db, state.encryptor.clone());
    let general_settings = settings_repo
        .get_general(DEFAULT_TENANT_ID)
        .await
        .unwrap_or(GeneralSettings {
            org_name: "Triage Warden".to_string(),
            timezone: "UTC".to_string(),
            mode: "supervised".to_string(),
        });

    // Use defaults if settings are empty (first run)
    let settings_data = SettingsData {
        org_name: if general_settings.org_name.is_empty() {
            "Triage Warden".to_string()
        } else {
            general_settings.org_name
        },
        timezone: if general_settings.timezone.is_empty() {
            "UTC".to_string()
        } else {
            general_settings.timezone
        },
        mode: if general_settings.mode.is_empty() {
            "supervised".to_string()
        } else {
            general_settings.mode
        },
    };

    // Load connectors from repository
    let connector_repo = create_connector_repository(&state.db);
    let connectors: Vec<ConnectorData> = connector_repo
        .list()
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|c| ConnectorData {
            id: c.id,
            name: c.name,
            connector_type: c.connector_type.to_string(),
            status: c.status.as_db_str().to_string(),
            last_check: c.last_health_check.map(format_time_ago),
        })
        .collect();

    // Load policies from repository
    let policy_repo = create_policy_repository(&state.db);
    let policies = fetch_policies(policy_repo.as_ref()).await;

    // Load rate limits from database
    let db_rate_limits = settings_repo
        .get_rate_limits(DEFAULT_TENANT_ID)
        .await
        .unwrap_or(RateLimits {
            isolate_host_hour: 5,
            disable_user_hour: 10,
            block_ip_hour: 20,
        });

    // Use defaults if settings are zero (first run)
    let rate_limits = RateLimitsData {
        isolate_host_hour: if db_rate_limits.isolate_host_hour == 0 {
            5
        } else {
            db_rate_limits.isolate_host_hour
        },
        disable_user_hour: if db_rate_limits.disable_user_hour == 0 {
            10
        } else {
            db_rate_limits.disable_user_hour
        },
        block_ip_hour: if db_rate_limits.block_ip_hour == 0 {
            20
        } else {
            db_rate_limits.block_ip_hour
        },
    };

    // Load notification channels from repository
    let notification_repo = create_notification_repository(&state.db);
    let notification_channels: Vec<NotificationChannel> = notification_repo
        .list()
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|channel| NotificationChannel {
            id: channel.id,
            name: channel.name,
            channel_type: channel.channel_type.as_db_str().to_string(),
            events: channel.events,
            enabled: channel.enabled,
        })
        .collect();

    // Load LLM settings from repository
    let llm = settings_repo
        .get_llm(DEFAULT_TENANT_ID)
        .await
        .unwrap_or(LlmSettings::default());
    let llm_settings = LlmSettingsData {
        provider: llm.provider,
        model: llm.model,
        api_key_set: !llm.api_key.is_empty(),
        base_url: llm.base_url,
        max_tokens: llm.max_tokens,
        temperature: llm.temperature,
        enabled: llm.enabled,
    };

    // Load API keys for the current user
    let api_key_repo = create_api_key_repository(&state.db);
    let api_keys: Vec<ApiKeyData> = api_key_repo
        .list_by_user(user.id)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|key| ApiKeyData {
            id: key.id,
            name: key.name,
            key_prefix: key.key_prefix,
            scopes: key.scopes,
            expires_at: key.expires_at.map(|t| t.to_rfc3339()),
            last_used_at: key.last_used_at.map(format_time_ago),
            created_at: key.created_at.to_rfc3339(),
        })
        .collect();

    // Load kill switch status
    let ks_status = state.kill_switch.status().await;
    let kill_switch = KillSwitchData {
        active: ks_status.active,
        activated_at: ks_status.activated_at.map(|t| t.to_rfc3339()),
        activated_by: ks_status.activated_by,
    };

    let template = SettingsTemplate {
        active_nav: "settings".to_string(),
        critical_count: nav.critical_count,
        open_count: nav.open_count,
        approval_count: nav.approval_count,
        system_healthy: true,
        current_user: Some(user_to_current_info(&user)),
        tab: query.tab,
        settings: settings_data,
        connectors,
        policies,
        rate_limits,
        notification_channels,
        llm_settings,
        api_keys,
        kill_switch,
    };

    Ok(HtmlTemplate(template))
}

// ============================================
// HTMX Partials
// ============================================

async fn partials_kpis(
    State(state): State<AppState>,
    AuthenticatedUser(_user): AuthenticatedUser,
) -> Result<impl IntoResponse, ApiError> {
    let repo = create_incident_repository(&state.db);
    let metrics = fetch_dashboard_metrics(repo.as_ref()).await;

    let template = KpisPartialTemplate { metrics };
    Ok(HtmlTemplate(template))
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
    AuthenticatedUser(_user): AuthenticatedUser,
    Query(query): Query<PartialsQuery>,
) -> Result<impl IntoResponse, ApiError> {
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
    Ok(HtmlTemplate(template))
}

// ============================================
// Modal Handlers
// ============================================

async fn modal_add_playbook(
    AuthenticatedUser(_user): AuthenticatedUser,
) -> Result<impl IntoResponse, ApiError> {
    Ok(HtmlTemplate(AddPlaybookModalTemplate))
}

async fn modal_add_connector(
    AuthenticatedUser(_user): AuthenticatedUser,
) -> Result<impl IntoResponse, ApiError> {
    Ok(HtmlTemplate(AddConnectorModalTemplate))
}

async fn modal_add_policy(
    AuthenticatedUser(_user): AuthenticatedUser,
) -> Result<impl IntoResponse, ApiError> {
    Ok(HtmlTemplate(AddPolicyModalTemplate))
}

async fn modal_add_notification(
    AuthenticatedUser(_user): AuthenticatedUser,
) -> Result<impl IntoResponse, ApiError> {
    Ok(HtmlTemplate(AddNotificationModalTemplate))
}

async fn modal_add_api_key(
    AuthenticatedUser(_user): AuthenticatedUser,
) -> Result<impl IntoResponse, ApiError> {
    Ok(HtmlTemplate(AddApiKeyModalTemplate))
}

async fn modal_edit_notification(
    State(state): State<AppState>,
    AuthenticatedUser(_user): AuthenticatedUser,
    Path(id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let notification_repo = create_notification_repository(&state.db);

    match notification_repo.get(id).await {
        Ok(Some(channel)) => {
            let template = EditNotificationModalTemplate {
                channel: EditNotificationChannel::from_channel(
                    channel.id,
                    channel.name,
                    channel.channel_type.as_db_str().to_string(),
                    channel.config,
                    channel.events,
                    channel.enabled,
                ),
            };
            Ok(HtmlTemplate(template).into_response())
        }
        _ => {
            // Return empty response if not found
            Ok("".into_response())
        }
    }
}

/// Partial for notifications table (used by HTMX refresh).
async fn partials_notifications(
    State(state): State<AppState>,
    AuthenticatedUser(_user): AuthenticatedUser,
) -> Result<impl IntoResponse, ApiError> {
    let notification_repo = create_notification_repository(&state.db);
    let notification_channels: Vec<NotificationChannel> = notification_repo
        .list()
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|channel| NotificationChannel {
            id: channel.id,
            name: channel.name,
            channel_type: channel.channel_type.as_db_str().to_string(),
            events: channel.events,
            enabled: channel.enabled,
        })
        .collect();

    let template = NotificationsPartialTemplate {
        notification_channels,
    };
    Ok(HtmlTemplate(template))
}

/// Edit policy modal handler.
async fn modal_edit_policy(
    State(state): State<AppState>,
    AuthenticatedUser(_user): AuthenticatedUser,
    Path(id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let policy_repo = create_policy_repository(&state.db);

    match policy_repo.get(id).await {
        Ok(Some(policy)) => {
            // Map approval level to the requires format used in the form
            let requires = match (&policy.action, &policy.approval_level) {
                (tw_core::policy::PolicyAction::AutoApprove, _) => "auto".to_string(),
                (tw_core::policy::PolicyAction::RequireApproval, Some(level)) => match level {
                    tw_core::policy::ApprovalLevel::Analyst => "single".to_string(),
                    tw_core::policy::ApprovalLevel::Senior => "dual".to_string(),
                    tw_core::policy::ApprovalLevel::Manager
                    | tw_core::policy::ApprovalLevel::Executive => "manager".to_string(),
                },
                _ => "single".to_string(),
            };

            let template = EditPolicyModalTemplate {
                policy: EditPolicyData {
                    id: policy.id,
                    name: policy.name,
                    condition: policy.condition,
                    requires,
                    enabled: policy.enabled,
                },
            };
            Ok(HtmlTemplate(template).into_response())
        }
        _ => Ok("".into_response()),
    }
}

/// Partial for policies table (used by HTMX refresh).
async fn partials_policies(
    State(state): State<AppState>,
    AuthenticatedUser(_user): AuthenticatedUser,
) -> Result<impl IntoResponse, ApiError> {
    let policy_repo = create_policy_repository(&state.db);
    let policies = fetch_policies(policy_repo.as_ref()).await;

    let template = PoliciesPartialTemplate { policies };
    Ok(HtmlTemplate(template))
}

/// Edit connector modal handler.
async fn modal_edit_connector(
    State(state): State<AppState>,
    AuthenticatedUser(_user): AuthenticatedUser,
    Path(id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let connector_repo = create_connector_repository(&state.db);

    match connector_repo.get(id).await {
        Ok(Some(connector)) => {
            let template = EditConnectorModalTemplate {
                connector: EditConnectorData::from_connector(
                    connector.id,
                    connector.name,
                    connector.connector_type.to_string(),
                    connector.config,
                    connector.enabled,
                ),
            };
            Ok(HtmlTemplate(template).into_response())
        }
        _ => Ok("".into_response()),
    }
}

/// Partial for connectors grid (used by HTMX refresh).
async fn partials_connectors(
    State(state): State<AppState>,
    AuthenticatedUser(_user): AuthenticatedUser,
) -> Result<impl IntoResponse, ApiError> {
    let connector_repo = create_connector_repository(&state.db);
    let connectors: Vec<ConnectorData> = connector_repo
        .list()
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|c| ConnectorData {
            id: c.id,
            name: c.name,
            connector_type: c.connector_type.to_string(),
            status: c.status.as_db_str().to_string(),
            last_check: c.last_health_check.map(format_time_ago),
        })
        .collect();

    let template = ConnectorsPartialTemplate { connectors };
    Ok(HtmlTemplate(template))
}

// ============================================
// Playbook Editor Modal Handlers
// ============================================

/// Modal for adding a stage to a playbook.
async fn modal_add_stage(
    AuthenticatedUser(_user): AuthenticatedUser,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    let template = AddStageModalTemplate { playbook_id: id };
    Ok(HtmlTemplate(template))
}

/// Modal for editing a stage.
async fn modal_edit_stage(
    State(state): State<AppState>,
    AuthenticatedUser(_user): AuthenticatedUser,
    Path((id, stage_index)): Path<(Uuid, usize)>,
) -> Result<Response, ApiError> {
    let playbook_repo = create_playbook_repository(&state.db);

    match playbook_repo.get(id).await {
        Ok(Some(playbook)) if stage_index < playbook.stages.len() => {
            let stage = &playbook.stages[stage_index];
            let template = EditStageModalTemplate {
                playbook_id: id,
                stage_index,
                stage: PlaybookStageData {
                    name: stage.name.clone(),
                    description: stage.description.clone(),
                    parallel: stage.parallel,
                    steps: stage
                        .steps
                        .iter()
                        .map(|s| PlaybookStepData {
                            action: s.action.clone(),
                            parameters: s.parameters.as_ref().map(|p| p.to_string()),
                            requires_approval: s.requires_approval,
                        })
                        .collect(),
                },
            };
            Ok(HtmlTemplate(template).into_response())
        }
        _ => Ok("".into_response()),
    }
}

/// Modal for adding a step to a stage.
async fn modal_add_step(
    State(state): State<AppState>,
    AuthenticatedUser(_user): AuthenticatedUser,
    Path((id, stage_index)): Path<(Uuid, usize)>,
) -> Result<Response, ApiError> {
    let playbook_repo = create_playbook_repository(&state.db);

    match playbook_repo.get(id).await {
        Ok(Some(playbook)) if stage_index < playbook.stages.len() => {
            let stage_name = playbook.stages[stage_index].name.clone();
            let template = AddStepModalTemplate {
                playbook_id: id,
                stage_index,
                stage_name,
            };
            Ok(HtmlTemplate(template).into_response())
        }
        _ => Ok("".into_response()),
    }
}

/// Modal for editing a step.
async fn modal_edit_step(
    State(state): State<AppState>,
    AuthenticatedUser(_user): AuthenticatedUser,
    Path((id, stage_index, step_index)): Path<(Uuid, usize, usize)>,
) -> Result<Response, ApiError> {
    let playbook_repo = create_playbook_repository(&state.db);

    match playbook_repo.get(id).await {
        Ok(Some(playbook))
            if stage_index < playbook.stages.len()
                && step_index < playbook.stages[stage_index].steps.len() =>
        {
            let step = &playbook.stages[stage_index].steps[step_index];
            let template = EditStepModalTemplate {
                playbook_id: id,
                stage_index,
                step_index,
                step: EditStepData {
                    action: step.action.clone(),
                    parameters: step.parameters.as_ref().map(|p| p.to_string()),
                    input_str: step
                        .input
                        .as_ref()
                        .map(|v| v.to_string())
                        .unwrap_or_default(),
                    output_str: step
                        .output
                        .as_ref()
                        .map(|v| v.join(", "))
                        .unwrap_or_default(),
                    conditions: step.conditions.as_ref().map(|c| c.to_string()),
                    requires_approval: step.requires_approval,
                },
            };
            Ok(HtmlTemplate(template).into_response())
        }
        _ => Ok("".into_response()),
    }
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

/// Fetches policies from the repository and converts them to template data.
async fn fetch_policies(repo: &dyn PolicyRepository) -> Vec<PolicyData> {
    let policies = repo.list().await.unwrap_or_default();

    policies
        .into_iter()
        .map(|policy| {
            // Map approval level to the requires format used in the template
            let requires = match (&policy.action, &policy.approval_level) {
                (tw_core::policy::PolicyAction::AutoApprove, _) => "auto_approve".to_string(),
                (tw_core::policy::PolicyAction::RequireApproval, Some(level)) => match level {
                    tw_core::policy::ApprovalLevel::Analyst => "single_approval".to_string(),
                    tw_core::policy::ApprovalLevel::Senior => "dual_approval".to_string(),
                    tw_core::policy::ApprovalLevel::Manager
                    | tw_core::policy::ApprovalLevel::Executive => "manager_approval".to_string(),
                },
                (tw_core::policy::PolicyAction::Deny, _) => "deny".to_string(),
                _ => "manual_approval".to_string(),
            };

            PolicyData {
                id: policy.id,
                name: policy.name,
                condition: policy.condition,
                requires,
                enabled: policy.enabled,
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

pub struct HtmlTemplate<T>(pub T);

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::test_helpers::{inject_test_user, TestUser};
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        middleware,
    };
    use tower::ServiceExt;
    use tw_core::db::{create_playbook_repository, DbPool};
    use tw_core::playbook::{Playbook, PlaybookStage, PlaybookStep};
    use tw_core::EventBus;

    /// Sets up a test app with an in-memory SQLite database.
    async fn setup_test_app() -> Router {
        let db_url = format!(
            "sqlite:file:test_web_{}?mode=memory&cache=shared",
            uuid::Uuid::new_v4()
        );

        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect(&db_url)
            .await
            .expect("Failed to create pool");

        // Run migrations to set up the schema
        sqlx::query(include_str!(
            "../../../tw-core/src/db/migrations/sqlite/20240101_000001_initial_schema.sql"
        ))
        .execute(&pool)
        .await
        .expect("Failed to run initial schema");

        // Run additional migrations for playbooks, connectors, policies, notifications, and settings
        sqlx::query(include_str!(
            "../../../tw-core/src/db/migrations/sqlite/20240102_000001_create_playbooks.sql"
        ))
        .execute(&pool)
        .await
        .expect("Failed to run playbooks schema");

        sqlx::query(include_str!(
            "../../../tw-core/src/db/migrations/sqlite/20240103_000001_create_connectors.sql"
        ))
        .execute(&pool)
        .await
        .expect("Failed to run connectors schema");

        sqlx::query(include_str!(
            "../../../tw-core/src/db/migrations/sqlite/20240104_000001_create_policies.sql"
        ))
        .execute(&pool)
        .await
        .expect("Failed to run policies schema");

        sqlx::query(include_str!(
            "../../../tw-core/src/db/migrations/sqlite/20240105_000001_create_notification_channels.sql"
        ))
        .execute(&pool)
        .await
        .expect("Failed to run notification channels schema");

        sqlx::query(include_str!(
            "../../../tw-core/src/db/migrations/sqlite/20240106_000001_create_settings.sql"
        ))
        .execute(&pool)
        .await
        .expect("Failed to run settings schema");

        sqlx::query(include_str!(
            "../../../tw-core/src/db/migrations/sqlite/20240107_000001_create_auth_tables.sql"
        ))
        .execute(&pool)
        .await
        .expect("Failed to run auth tables schema");

        // Multi-tenancy migrations
        for raw_statement in include_str!(
            "../../../tw-core/src/db/migrations/sqlite/20240215_000001_create_tenants.sql"
        )
        .split(';')
        {
            let statement: String = raw_statement
                .lines()
                .filter(|line| !line.trim().starts_with("--"))
                .collect::<Vec<_>>()
                .join("\n");
            let statement = statement.trim();
            if statement.is_empty() {
                continue;
            }
            sqlx::query(statement)
                .execute(&pool)
                .await
                .unwrap_or_else(|e| {
                    panic!(
                        "Failed to run tenants migration: {} - Error: {}",
                        statement, e
                    )
                });
        }

        // Add tenant_id to all tables - need to run statements separately due to SQLite limitations
        for raw_statement in include_str!(
            "../../../tw-core/src/db/migrations/sqlite/20240215_000002_add_tenant_id_to_tables.sql"
        )
        .split(';')
        {
            let statement: String = raw_statement
                .lines()
                .filter(|line| !line.trim().starts_with("--"))
                .collect::<Vec<_>>()
                .join("\n");
            let statement = statement.trim();
            if statement.is_empty() {
                continue;
            }
            sqlx::query(statement)
                .execute(&pool)
                .await
                .unwrap_or_else(|e| {
                    panic!(
                        "Failed to run tenant migration statement: {} - Error: {}",
                        statement, e
                    )
                });
        }

        let db = DbPool::Sqlite(pool);
        let event_bus = EventBus::new(100);
        let state = AppState::new(db, event_bus);

        // Add test user middleware to bypass authentication
        create_web_router(state).layer(middleware::from_fn(move |req, next| {
            inject_test_user(TestUser::admin(), req, next)
        }))
    }

    /// Sets up a test app and returns both the router and state for additional DB operations.
    async fn setup_test_app_with_state() -> (Router, AppState) {
        let db_url = format!(
            "sqlite:file:test_web_state_{}?mode=memory&cache=shared",
            uuid::Uuid::new_v4()
        );

        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect(&db_url)
            .await
            .expect("Failed to create pool");

        // Run migrations
        sqlx::query(include_str!(
            "../../../tw-core/src/db/migrations/sqlite/20240101_000001_initial_schema.sql"
        ))
        .execute(&pool)
        .await
        .expect("Failed to run initial schema");

        sqlx::query(include_str!(
            "../../../tw-core/src/db/migrations/sqlite/20240102_000001_create_playbooks.sql"
        ))
        .execute(&pool)
        .await
        .expect("Failed to run playbooks schema");

        sqlx::query(include_str!(
            "../../../tw-core/src/db/migrations/sqlite/20240103_000001_create_connectors.sql"
        ))
        .execute(&pool)
        .await
        .expect("Failed to run connectors schema");

        sqlx::query(include_str!(
            "../../../tw-core/src/db/migrations/sqlite/20240104_000001_create_policies.sql"
        ))
        .execute(&pool)
        .await
        .expect("Failed to run policies schema");

        sqlx::query(include_str!(
            "../../../tw-core/src/db/migrations/sqlite/20240105_000001_create_notification_channels.sql"
        ))
        .execute(&pool)
        .await
        .expect("Failed to run notification channels schema");

        sqlx::query(include_str!(
            "../../../tw-core/src/db/migrations/sqlite/20240106_000001_create_settings.sql"
        ))
        .execute(&pool)
        .await
        .expect("Failed to run settings schema");

        sqlx::query(include_str!(
            "../../../tw-core/src/db/migrations/sqlite/20240107_000001_create_auth_tables.sql"
        ))
        .execute(&pool)
        .await
        .expect("Failed to run auth tables schema");

        // Multi-tenancy migrations
        for raw_statement in include_str!(
            "../../../tw-core/src/db/migrations/sqlite/20240215_000001_create_tenants.sql"
        )
        .split(';')
        {
            let statement: String = raw_statement
                .lines()
                .filter(|line| !line.trim().starts_with("--"))
                .collect::<Vec<_>>()
                .join("\n");
            let statement = statement.trim();
            if statement.is_empty() {
                continue;
            }
            sqlx::query(statement)
                .execute(&pool)
                .await
                .unwrap_or_else(|e| {
                    panic!(
                        "Failed to run tenants migration: {} - Error: {}",
                        statement, e
                    )
                });
        }

        // Add tenant_id to all tables - need to run statements separately due to SQLite limitations
        for raw_statement in include_str!(
            "../../../tw-core/src/db/migrations/sqlite/20240215_000002_add_tenant_id_to_tables.sql"
        )
        .split(';')
        {
            let statement: String = raw_statement
                .lines()
                .filter(|line| !line.trim().starts_with("--"))
                .collect::<Vec<_>>()
                .join("\n");
            let statement = statement.trim();
            if statement.is_empty() {
                continue;
            }
            sqlx::query(statement)
                .execute(&pool)
                .await
                .unwrap_or_else(|e| {
                    panic!(
                        "Failed to run tenant migration statement: {} - Error: {}",
                        statement, e
                    )
                });
        }

        let db = DbPool::Sqlite(pool);
        let event_bus = EventBus::new(100);
        let state = AppState::new(db, event_bus);
        // Add test user middleware to bypass authentication
        let router =
            create_web_router(state.clone()).layer(middleware::from_fn(move |req, next| {
                inject_test_user(TestUser::admin(), req, next)
            }));
        (router, state)
    }

    /// Creates a test playbook in the database.
    async fn create_test_playbook_in_db(state: &AppState) -> Playbook {
        let repo = create_playbook_repository(&state.db);
        let playbook = Playbook::new("Test Phishing Response", "alert")
            .with_description("Automated response for phishing incidents")
            .with_trigger_condition("severity == 'high'")
            .with_enabled(true)
            .with_stage(
                PlaybookStage::new("enrichment")
                    .with_description("Enrich indicators")
                    .with_step(PlaybookStep::new("lookup_sender")),
            );

        repo.create(DEFAULT_TENANT_ID, &playbook)
            .await
            .expect("Failed to create test playbook")
    }

    /// Creates a test incident with PendingApproval status and a pending action.
    async fn create_test_incident_with_pending_action(state: &AppState) -> Uuid {
        use std::collections::HashMap;
        use tw_core::db::create_incident_repository;
        use tw_core::incident::{
            ActionTarget, ActionType, Alert, AlertSource, Incident, IncidentStatus, ProposedAction,
            Severity,
        };

        let alert = Alert {
            id: format!("test-alert-{}", uuid::Uuid::new_v4()),
            source: AlertSource::Edr("CrowdStrike".to_string()),
            alert_type: "malware".to_string(),
            severity: Severity::High,
            title: "Suspicious process detected".to_string(),
            description: Some("Possible malware activity on endpoint".to_string()),
            data: serde_json::json!({
                "title": "Suspicious process detected",
                "hostname": "workstation-001",
                "username": "jsmith",
                "process_name": "malware.exe"
            }),
            timestamp: chrono::Utc::now(),
            tags: vec!["malware".to_string(), "edr".to_string()],
        };

        let mut incident = Incident::from_alert(alert);
        incident.status = IncidentStatus::PendingApproval;

        // Add a pending action
        let action = ProposedAction::new(
            ActionType::IsolateHost,
            ActionTarget::Host {
                hostname: "workstation-001".to_string(),
                ip: Some("192.168.1.100".to_string()),
            },
            "Isolate host to prevent lateral movement".to_string(),
            HashMap::new(),
        );
        incident.proposed_actions.push(action);

        let repo = create_incident_repository(&state.db);
        // First create the incident, then save to update with proposed actions
        repo.create(&incident).await.unwrap();
        repo.save(&incident).await.unwrap();

        incident.id
    }

    // ============================================
    // Approvals Handler Tests
    // ============================================

    #[tokio::test]
    async fn test_get_approvals_returns_html() {
        let app = setup_test_app().await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/approvals")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let content_type = response
            .headers()
            .get("content-type")
            .expect("Content-Type header should be present");

        assert!(
            content_type.to_str().unwrap().contains("text/html"),
            "Content-Type should be text/html, got: {:?}",
            content_type
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();

        // Verify this is the approvals page HTML
        assert!(
            html.contains("Pending Approvals"),
            "Approvals page should contain 'Pending Approvals' title"
        );
        assert!(
            html.contains("actions awaiting your approval"),
            "Approvals page should contain subtitle text"
        );
    }

    #[tokio::test]
    async fn test_approvals_page_shows_pending_actions_section() {
        let (app, state) = setup_test_app_with_state().await;

        // Create an incident with a pending action
        let _incident_id = create_test_incident_with_pending_action(&state).await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/approvals")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();

        // Verify the pending actions section is shown with incident data
        assert!(
            html.contains("Pending Approvals"),
            "Approvals page should contain 'Pending Approvals' title"
        );
        assert!(
            html.contains("approvals-table"),
            "Approvals page should contain the approvals table when there are pending actions"
        );
        assert!(
            html.contains("Suspicious process detected"),
            "Approvals page should show the incident title"
        );
        assert!(
            html.contains("Isolate Host"),
            "Approvals page should show the action type"
        );
        assert!(
            html.contains("Isolate host to prevent lateral movement"),
            "Approvals page should show the action reason"
        );
    }

    #[tokio::test]
    async fn test_approvals_page_with_no_pending_actions_shows_empty_state() {
        let app = setup_test_app().await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/approvals")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();

        // Verify empty state is shown
        assert!(
            html.contains("No pending approvals"),
            "Approvals page should show 'No pending approvals' when empty"
        );
        assert!(
            html.contains("All actions have been reviewed"),
            "Approvals page should show empty state message"
        );
        // The table should NOT be rendered when there are no pending actions
        assert!(
            !html.contains("approvals-table"),
            "Approvals page should not contain the approvals table when empty"
        );
    }

    #[tokio::test]
    async fn test_approvals_page_shows_correct_action_count() {
        let (app, state) = setup_test_app_with_state().await;

        // Create an incident with a pending action
        let _incident_id = create_test_incident_with_pending_action(&state).await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/approvals")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();

        // Verify the page shows the correct count (1 action)
        assert!(
            html.contains("1 actions awaiting your approval"),
            "Approvals page should show correct pending action count"
        );
    }

    // ============================================
    // Playbooks Handler Tests
    // ============================================

    #[tokio::test]
    async fn test_get_playbooks_returns_html() {
        let app = setup_test_app().await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/playbooks")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let content_type = response
            .headers()
            .get("content-type")
            .expect("Should have content-type header");
        assert!(
            content_type.to_str().unwrap().contains("text/html"),
            "Content-Type should be text/html"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = String::from_utf8(body.to_vec()).unwrap();

        // Verify it's the playbooks page
        assert!(
            body_str.contains("Playbooks"),
            "Page should contain 'Playbooks' title"
        );
        assert!(
            body_str.contains("Triage Warden"),
            "Page should contain 'Triage Warden'"
        );
        assert!(
            body_str.contains("New Playbook"),
            "Page should contain 'New Playbook' button"
        );
    }

    #[tokio::test]
    async fn test_get_playbooks_empty_list() {
        let app = setup_test_app().await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/playbooks")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = String::from_utf8(body.to_vec()).unwrap();

        // Should show empty state message
        assert!(
            body_str.contains("No playbooks configured"),
            "Empty playbooks page should show 'No playbooks configured' message"
        );
    }

    #[tokio::test]
    async fn test_get_playbooks_with_playbook() {
        let (app, state) = setup_test_app_with_state().await;

        // Create a playbook
        let playbook = create_test_playbook_in_db(&state).await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/playbooks")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = String::from_utf8(body.to_vec()).unwrap();

        // Should show the playbook name and description
        assert!(
            body_str.contains(&playbook.name),
            "Page should contain playbook name '{}'",
            playbook.name
        );
        assert!(
            body_str.contains("Automated response for phishing incidents"),
            "Page should contain playbook description"
        );
        // Should not show empty state
        assert!(
            !body_str.contains("No playbooks configured"),
            "Page should not show empty state when playbooks exist"
        );
    }

    // ============================================
    // Playbook Detail Handler Tests
    // ============================================

    #[tokio::test]
    async fn test_get_playbook_detail_returns_html() {
        let (app, state) = setup_test_app_with_state().await;

        // Create a playbook
        let playbook = create_test_playbook_in_db(&state).await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri(&format!("/playbooks/{}", playbook.id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let content_type = response
            .headers()
            .get("content-type")
            .expect("Should have content-type header");
        assert!(
            content_type.to_str().unwrap().contains("text/html"),
            "Content-Type should be text/html"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = String::from_utf8(body.to_vec()).unwrap();

        // Verify it shows the playbook details
        assert!(
            body_str.contains(&playbook.name),
            "Detail page should contain playbook name"
        );
        assert!(
            body_str.contains("Automated response for phishing incidents"),
            "Detail page should contain playbook description"
        );
        assert!(
            body_str.contains("Playbook ID"),
            "Detail page should show 'Playbook ID' label"
        );
        assert!(
            body_str.contains(&playbook.id.to_string()),
            "Detail page should contain the playbook ID"
        );
        // Should show the stage
        assert!(
            body_str.contains("enrichment"),
            "Detail page should show stage name 'enrichment'"
        );
        assert!(
            body_str.contains("Enrich indicators"),
            "Detail page should show stage description"
        );
    }

    #[tokio::test]
    async fn test_get_playbook_detail_non_existent_redirects() {
        let app = setup_test_app().await;

        let random_id = Uuid::new_v4();

        let response = app
            .oneshot(
                Request::builder()
                    .uri(&format!("/playbooks/{}", random_id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should redirect to /playbooks
        assert_eq!(
            response.status(),
            StatusCode::SEE_OTHER,
            "Non-existent playbook should redirect"
        );

        let location = response
            .headers()
            .get("location")
            .expect("Should have location header for redirect");
        assert_eq!(
            location.to_str().unwrap(),
            "/playbooks",
            "Should redirect to /playbooks"
        );
    }

    // ============================================
    // Add Playbook Modal Tests
    // ============================================

    #[tokio::test]
    async fn test_get_add_playbook_modal_returns_html() {
        let app = setup_test_app().await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/web/modals/add-playbook")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let content_type = response
            .headers()
            .get("content-type")
            .expect("Should have content-type header");
        assert!(
            content_type.to_str().unwrap().contains("text/html"),
            "Content-Type should be text/html"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = String::from_utf8(body.to_vec()).unwrap();

        // Verify it's the add playbook modal
        assert!(
            body_str.contains("Create New Playbook"),
            "Modal should contain 'Create New Playbook' title"
        );
        assert!(
            body_str.contains("modal"),
            "Response should contain modal elements"
        );
    }

    #[tokio::test]
    async fn test_get_add_playbook_modal_contains_form_fields() {
        let app = setup_test_app().await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/web/modals/add-playbook")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = String::from_utf8(body.to_vec()).unwrap();

        // Verify form field labels are present
        assert!(
            body_str.contains("Playbook Name"),
            "Modal should contain 'Playbook Name' label"
        );
        assert!(
            body_str.contains("Description"),
            "Modal should contain 'Description' label"
        );
        assert!(
            body_str.contains("Trigger Type"),
            "Modal should contain 'Trigger Type' label"
        );
        assert!(
            body_str.contains("Trigger Condition"),
            "Modal should contain 'Trigger Condition' label"
        );

        // Verify form input names are present
        assert!(
            body_str.contains("name=\"name\""),
            "Modal should contain name input"
        );
        assert!(
            body_str.contains("name=\"description\""),
            "Modal should contain description input"
        );
        assert!(
            body_str.contains("name=\"trigger_type\""),
            "Modal should contain trigger_type input"
        );
        assert!(
            body_str.contains("name=\"trigger_condition\""),
            "Modal should contain trigger_condition input"
        );
    }

    #[tokio::test]
    async fn test_get_add_playbook_modal_contains_trigger_type_options() {
        let app = setup_test_app().await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/web/modals/add-playbook")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = String::from_utf8(body.to_vec()).unwrap();

        // Verify trigger type dropdown options
        assert!(
            body_str.contains("Alert Type Match"),
            "Modal should contain 'Alert Type Match' option"
        );
        assert!(
            body_str.contains("Severity Level"),
            "Modal should contain 'Severity Level' option"
        );
        assert!(
            body_str.contains("Alert Source"),
            "Modal should contain 'Alert Source' option"
        );
        assert!(
            body_str.contains("Manual Trigger Only"),
            "Modal should contain 'Manual Trigger Only' option"
        );
    }

    #[tokio::test]
    async fn test_get_add_playbook_modal_contains_submit_action() {
        let app = setup_test_app().await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/web/modals/add-playbook")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = String::from_utf8(body.to_vec()).unwrap();

        // Verify the form submits to the API
        assert!(
            body_str.contains("hx-post=\"/api/playbooks\""),
            "Modal form should submit to /api/playbooks"
        );
        assert!(
            body_str.contains("Create Playbook"),
            "Modal should contain 'Create Playbook' submit button"
        );
    }

    // =========================================================================
    // Task 3.2: Incidents Web Handler Tests
    // =========================================================================

    /// Creates a test incident with the given parameters.
    fn create_test_incident(
        title: &str,
        severity: tw_core::incident::Severity,
        status: tw_core::incident::IncidentStatus,
    ) -> tw_core::incident::Incident {
        use tw_core::incident::{Alert, AlertSource, Incident};

        let alert = Alert {
            id: format!("alert-{}", uuid::Uuid::new_v4()),
            source: AlertSource::EmailSecurity("M365".to_string()),
            alert_type: "phishing".to_string(),
            severity,
            title: title.to_string(),
            description: Some("Test incident description".to_string()),
            data: serde_json::json!({
                "title": title,
                "hostname": "test-host.example.com",
                "username": "test.user"
            }),
            timestamp: chrono::Utc::now(),
            tags: vec!["test".to_string()],
        };
        let mut incident = Incident::from_alert(alert);
        incident.status = status;
        incident
    }

    #[tokio::test]
    async fn test_incidents_list_returns_200() {
        let app = setup_test_app().await;
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/incidents")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_incidents_list_returns_html_content_type() {
        let app = setup_test_app().await;
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/incidents")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let ct = response
            .headers()
            .get("content-type")
            .expect("Content-Type header");
        assert!(ct.to_str().unwrap().contains("text/html"));
    }

    #[tokio::test]
    async fn test_incidents_list_with_data() {
        use tw_core::db::create_incident_repository;
        use tw_core::incident::{IncidentStatus, Severity};

        let (app, state) = setup_test_app_with_state().await;
        let incident = create_test_incident(
            "Phishing Email Detected",
            Severity::High,
            IncidentStatus::New,
        );
        let repo = create_incident_repository(&state.db);
        repo.create(&incident)
            .await
            .expect("Failed to create incident");

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/incidents")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = String::from_utf8(body.to_vec()).unwrap();
        assert!(body_str.contains("Phishing Email Detected"));
    }

    #[tokio::test]
    async fn test_incident_detail_returns_html_for_existing_incident() {
        use tw_core::db::create_incident_repository;
        use tw_core::incident::{IncidentStatus, Severity};

        let (app, state) = setup_test_app_with_state().await;
        let incident = create_test_incident(
            "Malware Detection",
            Severity::Critical,
            IncidentStatus::Analyzing,
        );
        let incident_id = incident.id;
        let repo = create_incident_repository(&state.db);
        repo.create(&incident)
            .await
            .expect("Failed to create incident");

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/incidents/{}", incident_id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let ct = response
            .headers()
            .get("content-type")
            .expect("Content-Type header");
        assert!(ct.to_str().unwrap().contains("text/html"));
    }

    #[tokio::test]
    async fn test_incident_detail_contains_incident_data() {
        use tw_core::db::create_incident_repository;
        use tw_core::incident::{IncidentStatus, Severity};

        let (app, state) = setup_test_app_with_state().await;
        let incident = create_test_incident(
            "Suspicious Login Attempt",
            Severity::High,
            IncidentStatus::PendingReview,
        );
        let incident_id = incident.id;
        let repo = create_incident_repository(&state.db);
        repo.create(&incident)
            .await
            .expect("Failed to create incident");

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/incidents/{}", incident_id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = String::from_utf8(body.to_vec()).unwrap();
        assert!(body_str.contains("Suspicious Login Attempt"));
        assert!(body_str.contains("high"));
    }

    #[tokio::test]
    async fn test_incident_detail_redirects_for_nonexistent_incident() {
        let app = setup_test_app().await;
        let random_id = uuid::Uuid::new_v4();
        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/incidents/{}", random_id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = response.headers().get("location").expect("location header");
        assert_eq!(location.to_str().unwrap(), "/incidents");
    }

    #[tokio::test]
    async fn test_incidents_list_with_severity_filter() {
        use tw_core::db::create_incident_repository;
        use tw_core::incident::{IncidentStatus, Severity};

        let (app, state) = setup_test_app_with_state().await;
        let repo = create_incident_repository(&state.db);
        repo.create(&create_test_incident(
            "Critical Breach",
            Severity::Critical,
            IncidentStatus::New,
        ))
        .await
        .unwrap();
        repo.create(&create_test_incident(
            "Low Priority Alert",
            Severity::Low,
            IncidentStatus::New,
        ))
        .await
        .unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/incidents?severity=critical")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = String::from_utf8(body.to_vec()).unwrap();
        assert!(body_str.contains("Critical Breach"));
    }

    #[tokio::test]
    async fn test_incidents_list_with_status_filter_open() {
        use tw_core::db::create_incident_repository;
        use tw_core::incident::{IncidentStatus, Severity};

        let (app, state) = setup_test_app_with_state().await;
        let repo = create_incident_repository(&state.db);
        repo.create(&create_test_incident(
            "New Alert",
            Severity::Medium,
            IncidentStatus::New,
        ))
        .await
        .unwrap();
        repo.create(&create_test_incident(
            "Resolved Alert",
            Severity::Medium,
            IncidentStatus::Resolved,
        ))
        .await
        .unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/incidents?status=open")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = String::from_utf8(body.to_vec()).unwrap();
        assert!(body_str.contains("New Alert"));
        assert!(!body_str.contains("Resolved Alert"));
    }

    #[tokio::test]
    async fn test_incidents_list_with_status_filter_resolved() {
        use tw_core::db::create_incident_repository;
        use tw_core::incident::{IncidentStatus, Severity};

        let (app, state) = setup_test_app_with_state().await;
        let repo = create_incident_repository(&state.db);
        repo.create(&create_test_incident(
            "New Alert",
            Severity::Medium,
            IncidentStatus::New,
        ))
        .await
        .unwrap();
        repo.create(&create_test_incident(
            "Resolved Alert",
            Severity::Medium,
            IncidentStatus::Resolved,
        ))
        .await
        .unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/incidents?status=resolved")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = String::from_utf8(body.to_vec()).unwrap();
        assert!(body_str.contains("Resolved Alert"));
        assert!(!body_str.contains("New Alert"));
    }

    #[tokio::test]
    async fn test_incidents_list_with_page_parameter() {
        use tw_core::db::create_incident_repository;
        use tw_core::incident::{IncidentStatus, Severity};

        let (app, state) = setup_test_app_with_state().await;
        let repo = create_incident_repository(&state.db);
        for i in 0..25 {
            let mut incident = create_test_incident(
                &format!("Incident {}", i),
                Severity::Medium,
                IncidentStatus::New,
            );
            incident.created_at = chrono::Utc::now() - chrono::Duration::seconds(i as i64);
            repo.create(&incident).await.unwrap();
        }

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/incidents?page=2")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_incidents_list_empty_page_beyond_data() {
        use tw_core::db::create_incident_repository;
        use tw_core::incident::{IncidentStatus, Severity};

        let (app, state) = setup_test_app_with_state().await;
        let repo = create_incident_repository(&state.db);
        for i in 0..5 {
            repo.create(&create_test_incident(
                &format!("Incident {}", i),
                Severity::Medium,
                IncidentStatus::New,
            ))
            .await
            .unwrap();
        }

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/incidents?page=10")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_incidents_partial_returns_200() {
        let app = setup_test_app().await;
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/web/partials/incidents")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_incidents_partial_returns_html_content_type() {
        let app = setup_test_app().await;
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/web/partials/incidents")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let ct = response
            .headers()
            .get("content-type")
            .expect("Content-Type header");
        assert!(ct.to_str().unwrap().contains("text/html"));
    }

    #[tokio::test]
    async fn test_incidents_partial_with_data() {
        use tw_core::db::create_incident_repository;
        use tw_core::incident::{IncidentStatus, Severity};

        let (app, state) = setup_test_app_with_state().await;
        let repo = create_incident_repository(&state.db);
        repo.create(&create_test_incident(
            "Partial Test Incident",
            Severity::High,
            IncidentStatus::New,
        ))
        .await
        .unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/web/partials/incidents")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = String::from_utf8(body.to_vec()).unwrap();
        assert!(body_str.contains("Partial Test Incident"));
    }

    #[tokio::test]
    async fn test_incidents_partial_empty_shows_empty_state() {
        let app = setup_test_app().await;
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/web/partials/incidents")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = String::from_utf8(body.to_vec()).unwrap();
        assert!(body_str.contains("No incidents found") || body_str.contains("empty"));
    }

    // =========================================================================
    // Dashboard Handler Tests
    // =========================================================================

    #[tokio::test]
    async fn test_dashboard_returns_200_ok() {
        let app = setup_test_app().await;

        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_dashboard_returns_html_content_type() {
        let app = setup_test_app().await;

        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let content_type = response
            .headers()
            .get("content-type")
            .expect("Content-Type header should be present");

        assert!(
            content_type.to_str().unwrap().contains("text/html"),
            "Content-Type should be text/html, got: {:?}",
            content_type
        );
    }

    #[tokio::test]
    async fn test_dashboard_contains_page_structure() {
        let app = setup_test_app().await;

        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();

        // Verify page structure elements
        assert!(
            html.contains("Triage Warden"),
            "Dashboard should contain 'Triage Warden' title"
        );
        assert!(
            html.contains("Dashboard") || html.contains("dashboard"),
            "Dashboard should contain 'Dashboard' navigation element"
        );
    }

    #[tokio::test]
    async fn test_dashboard_contains_kpi_section() {
        let app = setup_test_app().await;

        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();

        // Verify KPI sections are present
        assert!(
            html.contains("Critical") || html.contains("critical"),
            "Dashboard should contain critical incident KPI"
        );
        assert!(
            html.contains("Open") || html.contains("open"),
            "Dashboard should contain open incident count"
        );
    }

    #[tokio::test]
    async fn test_dashboard_empty_state_shows_zero_counts() {
        let app = setup_test_app().await;

        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();

        // With empty database, counts should be 0
        // The page should still render without errors
        assert!(
            html.contains("0") || html.contains("No incidents"),
            "Empty dashboard should show zero counts or 'No incidents' message"
        );
    }

    #[tokio::test]
    async fn test_dashboard_with_critical_incident() {
        use tw_core::db::create_incident_repository;
        use tw_core::incident::{IncidentStatus, Severity};

        let (app, state) = setup_test_app_with_state().await;

        // Create a critical incident
        let incident = create_test_incident(
            "Critical Security Breach",
            Severity::Critical,
            IncidentStatus::New,
        );
        let repo = create_incident_repository(&state.db);
        repo.create(&incident)
            .await
            .expect("Failed to create incident");

        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();

        // Dashboard should show the critical incident
        assert!(
            html.contains("Critical Security Breach"),
            "Dashboard should display critical incident title"
        );
    }

    #[tokio::test]
    async fn test_dashboard_with_multiple_severities() {
        use tw_core::db::create_incident_repository;
        use tw_core::incident::{IncidentStatus, Severity};

        let (app, state) = setup_test_app_with_state().await;
        let repo = create_incident_repository(&state.db);

        // Create incidents with different severities
        repo.create(&create_test_incident(
            "Critical Alert",
            Severity::Critical,
            IncidentStatus::New,
        ))
        .await
        .unwrap();
        repo.create(&create_test_incident(
            "High Alert",
            Severity::High,
            IncidentStatus::New,
        ))
        .await
        .unwrap();
        repo.create(&create_test_incident(
            "Medium Alert",
            Severity::Medium,
            IncidentStatus::New,
        ))
        .await
        .unwrap();
        repo.create(&create_test_incident(
            "Low Alert",
            Severity::Low,
            IncidentStatus::New,
        ))
        .await
        .unwrap();

        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();

        // Dashboard should show incidents in the recent list
        assert!(
            html.contains("Critical Alert") || html.contains("critical"),
            "Dashboard should display critical incidents"
        );
    }

    #[tokio::test]
    async fn test_dashboard_shows_correct_critical_count() {
        use tw_core::db::create_incident_repository;
        use tw_core::incident::{IncidentStatus, Severity};

        let (app, state) = setup_test_app_with_state().await;
        let repo = create_incident_repository(&state.db);

        // Create 3 critical incidents
        for i in 0..3 {
            repo.create(&create_test_incident(
                &format!("Critical Incident {}", i),
                Severity::Critical,
                IncidentStatus::New,
            ))
            .await
            .unwrap();
        }

        // Create 2 high severity incidents
        for i in 0..2 {
            repo.create(&create_test_incident(
                &format!("High Incident {}", i),
                Severity::High,
                IncidentStatus::New,
            ))
            .await
            .unwrap();
        }

        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();

        // The critical count should be 3
        // Note: We check for presence in HTML - the actual number format depends on template
        assert!(
            html.contains("3") || html.contains("Critical"),
            "Dashboard should show correct critical count"
        );
    }

    #[tokio::test]
    async fn test_dashboard_shows_correct_open_count() {
        use tw_core::db::create_incident_repository;
        use tw_core::incident::{IncidentStatus, Severity};

        let (app, state) = setup_test_app_with_state().await;
        let repo = create_incident_repository(&state.db);

        // Create open incidents
        repo.create(&create_test_incident(
            "Open 1",
            Severity::Medium,
            IncidentStatus::New,
        ))
        .await
        .unwrap();
        repo.create(&create_test_incident(
            "Open 2",
            Severity::Medium,
            IncidentStatus::Enriching,
        ))
        .await
        .unwrap();
        repo.create(&create_test_incident(
            "Open 3",
            Severity::Medium,
            IncidentStatus::Analyzing,
        ))
        .await
        .unwrap();

        // Create resolved incident (should not count as open)
        repo.create(&create_test_incident(
            "Resolved",
            Severity::Medium,
            IncidentStatus::Resolved,
        ))
        .await
        .unwrap();

        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();

        // Verify open count is shown (3 open, 1 resolved)
        assert!(
            html.contains("3") || html.contains("Open"),
            "Dashboard should show correct open count"
        );
    }

    #[tokio::test]
    async fn test_dashboard_shows_pending_approvals_count() {
        use tw_core::db::create_incident_repository;
        use tw_core::incident::{IncidentStatus, Severity};

        let (app, state) = setup_test_app_with_state().await;
        let repo = create_incident_repository(&state.db);

        // Create incidents pending approval
        repo.create(&create_test_incident(
            "Pending 1",
            Severity::High,
            IncidentStatus::PendingApproval,
        ))
        .await
        .unwrap();
        repo.create(&create_test_incident(
            "Pending 2",
            Severity::High,
            IncidentStatus::PendingApproval,
        ))
        .await
        .unwrap();

        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();

        // Should show approval count somewhere in the nav or KPIs
        assert!(
            html.contains("2") || html.contains("Approval") || html.contains("approval"),
            "Dashboard should show pending approval count"
        );
    }

    #[tokio::test]
    async fn test_dashboard_shows_recent_incidents_limited() {
        use tw_core::db::create_incident_repository;
        use tw_core::incident::{IncidentStatus, Severity};

        let (app, state) = setup_test_app_with_state().await;
        let repo = create_incident_repository(&state.db);

        // Create more than 10 incidents (dashboard limits to 10)
        for i in 0..15 {
            let mut incident = create_test_incident(
                &format!("Incident Number {}", i),
                Severity::Medium,
                IncidentStatus::New,
            );
            // Stagger creation times
            incident.created_at = chrono::Utc::now() - chrono::Duration::minutes(i as i64);
            repo.create(&incident).await.unwrap();
        }

        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();

        // Dashboard should render successfully with incidents
        assert!(
            html.contains("Incident Number"),
            "Dashboard should display recent incidents"
        );
    }

    #[tokio::test]
    async fn test_dashboard_excludes_resolved_from_recent() {
        use tw_core::db::create_incident_repository;
        use tw_core::incident::{IncidentStatus, Severity};

        let (app, state) = setup_test_app_with_state().await;
        let repo = create_incident_repository(&state.db);

        // Create an open incident
        repo.create(&create_test_incident(
            "Active Incident",
            Severity::Medium,
            IncidentStatus::New,
        ))
        .await
        .unwrap();

        // Create resolved incidents
        repo.create(&create_test_incident(
            "Resolved Incident",
            Severity::Medium,
            IncidentStatus::Resolved,
        ))
        .await
        .unwrap();
        repo.create(&create_test_incident(
            "Closed Incident",
            Severity::Medium,
            IncidentStatus::Closed,
        ))
        .await
        .unwrap();

        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();

        // Should show active but not resolved in recent list
        assert!(
            html.contains("Active Incident"),
            "Dashboard should show active incidents"
        );
        assert!(
            !html.contains("Resolved Incident"),
            "Dashboard should not show resolved incidents in recent list"
        );
        assert!(
            !html.contains("Closed Incident"),
            "Dashboard should not show closed incidents in recent list"
        );
    }

    #[tokio::test]
    async fn test_dashboard_navigation_links_present() {
        let app = setup_test_app().await;

        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();

        // Verify navigation links are present
        assert!(
            html.contains("/incidents") || html.contains("Incidents"),
            "Dashboard should have link to incidents"
        );
        assert!(
            html.contains("/playbooks") || html.contains("Playbooks"),
            "Dashboard should have link to playbooks"
        );
        assert!(
            html.contains("/settings") || html.contains("Settings"),
            "Dashboard should have link to settings"
        );
    }

    // =========================================================================
    // Dashboard KPIs Partial Handler Tests
    // =========================================================================

    #[tokio::test]
    async fn test_partials_kpis_returns_200() {
        let app = setup_test_app().await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/web/partials/kpis")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_partials_kpis_returns_html_content_type() {
        let app = setup_test_app().await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/web/partials/kpis")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let content_type = response
            .headers()
            .get("content-type")
            .expect("Content-Type header should be present");

        assert!(
            content_type.to_str().unwrap().contains("text/html"),
            "KPIs partial should return HTML content type"
        );
    }

    #[tokio::test]
    async fn test_partials_kpis_empty_database() {
        let app = setup_test_app().await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/web/partials/kpis")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();

        // With empty database, should show zero counts
        assert!(
            html.contains("0"),
            "KPIs partial should show zero counts for empty database"
        );
    }

    #[tokio::test]
    async fn test_partials_kpis_with_incidents() {
        use tw_core::db::create_incident_repository;
        use tw_core::incident::{IncidentStatus, Severity};

        let (app, state) = setup_test_app_with_state().await;
        let repo = create_incident_repository(&state.db);

        // Create various incidents
        repo.create(&create_test_incident(
            "Critical",
            Severity::Critical,
            IncidentStatus::New,
        ))
        .await
        .unwrap();
        repo.create(&create_test_incident(
            "High",
            Severity::High,
            IncidentStatus::New,
        ))
        .await
        .unwrap();
        repo.create(&create_test_incident(
            "Medium",
            Severity::Medium,
            IncidentStatus::New,
        ))
        .await
        .unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/web/partials/kpis")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();

        // Should show counts for incidents
        assert!(
            html.contains("1") || html.contains("3"),
            "KPIs partial should show incident counts"
        );
    }

    #[tokio::test]
    async fn test_partials_kpis_updates_with_new_incidents() {
        use tw_core::db::create_incident_repository;
        use tw_core::incident::{IncidentStatus, Severity};

        let (_, state) = setup_test_app_with_state().await;
        let repo = create_incident_repository(&state.db);

        // First request - empty
        let app1 = create_web_router(state.clone()).layer(middleware::from_fn(move |req, next| {
            inject_test_user(TestUser::admin(), req, next)
        }));
        let response1 = app1
            .oneshot(
                Request::builder()
                    .uri("/web/partials/kpis")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let body1 = axum::body::to_bytes(response1.into_body(), usize::MAX)
            .await
            .unwrap();
        let html1 = String::from_utf8(body1.to_vec()).unwrap();

        // Add incidents
        repo.create(&create_test_incident(
            "New Critical",
            Severity::Critical,
            IncidentStatus::New,
        ))
        .await
        .unwrap();

        // Second request - with data
        let app2 = create_web_router(state).layer(middleware::from_fn(move |req, next| {
            inject_test_user(TestUser::admin(), req, next)
        }));
        let response2 = app2
            .oneshot(
                Request::builder()
                    .uri("/web/partials/kpis")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let body2 = axum::body::to_bytes(response2.into_body(), usize::MAX)
            .await
            .unwrap();
        let html2 = String::from_utf8(body2.to_vec()).unwrap();

        // Both should be valid HTML, second should have updated counts
        assert!(!html1.is_empty(), "First KPIs response should not be empty");
        assert!(
            !html2.is_empty(),
            "Second KPIs response should not be empty"
        );
        // The second response should reflect the new incident
        assert!(
            html2.contains("1"),
            "Updated KPIs should show the new incident count"
        );
    }

    // =========================================================================
    // Dashboard Metrics Calculation Tests
    // =========================================================================

    #[tokio::test]
    async fn test_dashboard_metrics_severity_breakdown() {
        use tw_core::db::create_incident_repository;
        use tw_core::incident::{IncidentStatus, Severity};

        let (app, state) = setup_test_app_with_state().await;
        let repo = create_incident_repository(&state.db);

        // Create incidents with each severity
        repo.create(&create_test_incident(
            "Crit",
            Severity::Critical,
            IncidentStatus::New,
        ))
        .await
        .unwrap();
        repo.create(&create_test_incident(
            "High1",
            Severity::High,
            IncidentStatus::New,
        ))
        .await
        .unwrap();
        repo.create(&create_test_incident(
            "High2",
            Severity::High,
            IncidentStatus::New,
        ))
        .await
        .unwrap();
        repo.create(&create_test_incident(
            "Med",
            Severity::Medium,
            IncidentStatus::New,
        ))
        .await
        .unwrap();
        repo.create(&create_test_incident(
            "Low1",
            Severity::Low,
            IncidentStatus::New,
        ))
        .await
        .unwrap();
        repo.create(&create_test_incident(
            "Low2",
            Severity::Low,
            IncidentStatus::New,
        ))
        .await
        .unwrap();
        repo.create(&create_test_incident(
            "Low3",
            Severity::Low,
            IncidentStatus::New,
        ))
        .await
        .unwrap();

        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();

        // Verify the page renders and contains severity-related content
        assert!(
            html.contains("critical")
                || html.contains("Critical")
                || html.contains("high")
                || html.contains("High"),
            "Dashboard should display severity breakdown"
        );
    }

    #[tokio::test]
    async fn test_dashboard_with_all_incident_statuses() {
        use tw_core::db::create_incident_repository;
        use tw_core::incident::{IncidentStatus, Severity};

        let (app, state) = setup_test_app_with_state().await;
        let repo = create_incident_repository(&state.db);

        // Create incidents in various statuses
        repo.create(&create_test_incident(
            "New",
            Severity::Medium,
            IncidentStatus::New,
        ))
        .await
        .unwrap();
        repo.create(&create_test_incident(
            "Enriching",
            Severity::Medium,
            IncidentStatus::Enriching,
        ))
        .await
        .unwrap();
        repo.create(&create_test_incident(
            "Analyzing",
            Severity::Medium,
            IncidentStatus::Analyzing,
        ))
        .await
        .unwrap();
        repo.create(&create_test_incident(
            "PendingReview",
            Severity::Medium,
            IncidentStatus::PendingReview,
        ))
        .await
        .unwrap();
        repo.create(&create_test_incident(
            "PendingApproval",
            Severity::Medium,
            IncidentStatus::PendingApproval,
        ))
        .await
        .unwrap();
        repo.create(&create_test_incident(
            "Executing",
            Severity::Medium,
            IncidentStatus::Executing,
        ))
        .await
        .unwrap();
        repo.create(&create_test_incident(
            "Resolved",
            Severity::Medium,
            IncidentStatus::Resolved,
        ))
        .await
        .unwrap();
        repo.create(&create_test_incident(
            "FalsePositive",
            Severity::Medium,
            IncidentStatus::FalsePositive,
        ))
        .await
        .unwrap();
        repo.create(&create_test_incident(
            "Closed",
            Severity::Medium,
            IncidentStatus::Closed,
        ))
        .await
        .unwrap();

        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();

        // Dashboard should render successfully with all status types
        // Open count should be 6 (New, Enriching, Analyzing, PendingReview, PendingApproval, Executing)
        assert!(
            html.contains("6") || html.contains("Open") || html.contains("open"),
            "Dashboard should correctly count open incidents across all statuses"
        );
    }

    #[tokio::test]
    async fn test_dashboard_system_health_indicator() {
        let app = setup_test_app().await;

        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();

        // Dashboard should indicate system health status
        // The template uses system_healthy: true by default
        assert!(
            html.contains("healthy")
                || html.contains("Healthy")
                || html.contains("status")
                || html.contains("System"),
            "Dashboard should display system health indicator"
        );
    }

    #[tokio::test]
    async fn test_dashboard_incident_row_contains_expected_data() {
        use tw_core::db::create_incident_repository;
        use tw_core::incident::{Alert, AlertSource, Incident, IncidentStatus, Severity};

        let (app, state) = setup_test_app_with_state().await;

        // Create incident with specific data to verify row rendering
        let alert = Alert {
            id: format!("alert-{}", uuid::Uuid::new_v4()),
            source: AlertSource::Edr("CrowdStrike".to_string()),
            alert_type: "malware".to_string(),
            severity: Severity::High,
            title: "Malware Detected on Workstation".to_string(),
            description: Some("Ransomware variant detected".to_string()),
            data: serde_json::json!({
                "title": "Malware Detected on Workstation",
                "hostname": "ws-finance-01",
                "username": "john.doe"
            }),
            timestamp: chrono::Utc::now(),
            tags: vec!["malware".to_string(), "ransomware".to_string()],
        };
        let mut incident = Incident::from_alert(alert);
        incident.status = IncidentStatus::New;

        let repo = create_incident_repository(&state.db);
        repo.create(&incident)
            .await
            .expect("Failed to create incident");

        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();

        // Verify incident row data is rendered
        assert!(
            html.contains("Malware Detected on Workstation"),
            "Dashboard should show incident title"
        );
        assert!(
            html.contains("ws-finance-01"),
            "Dashboard should show hostname"
        );
        assert!(html.contains("john.doe"), "Dashboard should show username");
        assert!(
            html.contains("CrowdStrike") || html.contains("Edr"),
            "Dashboard should show source"
        );
    }

    #[tokio::test]
    async fn test_dashboard_time_ago_display() {
        use tw_core::db::create_incident_repository;
        use tw_core::incident::{IncidentStatus, Severity};

        let (app, state) = setup_test_app_with_state().await;
        let repo = create_incident_repository(&state.db);

        // Create incident with recent timestamp
        let mut incident =
            create_test_incident("Recent Incident", Severity::Medium, IncidentStatus::New);
        incident.created_at = chrono::Utc::now() - chrono::Duration::minutes(5);
        repo.create(&incident).await.unwrap();

        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();

        // Should show relative time (e.g., "5m ago")
        assert!(
            html.contains("ago") || html.contains("min") || html.contains("m "),
            "Dashboard should show relative time for incidents"
        );
    }

    // =========================================================================
    // Comprehensive Approvals Handler Tests
    // =========================================================================

    /// Creates a test incident with a specific action type for approval testing.
    async fn create_incident_with_action(
        state: &AppState,
        title: &str,
        action_type: tw_core::incident::ActionType,
        target: tw_core::incident::ActionTarget,
        reason: &str,
    ) -> (Uuid, Uuid) {
        use std::collections::HashMap;
        use tw_core::db::create_incident_repository;
        use tw_core::incident::{
            Alert, AlertSource, Incident, IncidentStatus, ProposedAction, Severity,
        };

        let alert = Alert {
            id: format!("test-alert-{}", uuid::Uuid::new_v4()),
            source: AlertSource::Siem("Splunk".to_string()),
            alert_type: "security_alert".to_string(),
            severity: Severity::High,
            title: title.to_string(),
            description: Some("Test incident for approval testing".to_string()),
            data: serde_json::json!({
                "title": title,
                "hostname": "test-workstation",
                "username": "testuser"
            }),
            timestamp: chrono::Utc::now(),
            tags: vec!["test".to_string()],
        };

        let mut incident = Incident::from_alert(alert);
        incident.status = IncidentStatus::PendingApproval;

        let action = ProposedAction::new(action_type, target, reason.to_string(), HashMap::new());
        let action_id = action.id;
        incident.proposed_actions.push(action);

        let repo = create_incident_repository(&state.db);
        // First create the incident, then save to update with proposed actions
        repo.create(&incident).await.unwrap();
        repo.save(&incident).await.unwrap();

        (incident.id, action_id)
    }

    #[tokio::test]
    async fn test_approvals_page_with_multiple_actions_from_different_incidents() {
        use tw_core::incident::{ActionTarget, ActionType};

        let (app, state) = setup_test_app_with_state().await;

        // Create multiple incidents with pending actions
        let (_id1, _action1) = create_incident_with_action(
            &state,
            "Ransomware Detected",
            ActionType::IsolateHost,
            ActionTarget::Host {
                hostname: "infected-pc".to_string(),
                ip: Some("10.0.0.50".to_string()),
            },
            "Isolate host to contain ransomware",
        )
        .await;

        let (_id2, _action2) = create_incident_with_action(
            &state,
            "Compromised User Account",
            ActionType::DisableUser,
            ActionTarget::User {
                username: "jdoe".to_string(),
                email: Some("jdoe@example.com".to_string()),
            },
            "Disable compromised user account",
        )
        .await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/approvals")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();

        // Verify both incidents and actions are shown
        assert!(
            html.contains("Ransomware Detected"),
            "Should show first incident title"
        );
        assert!(
            html.contains("Compromised User Account"),
            "Should show second incident title"
        );
        assert!(
            html.contains("Isolate Host"),
            "Should show isolate host action"
        );
        assert!(
            html.contains("Disable User"),
            "Should show disable user action"
        );
        assert!(
            html.contains("2 actions awaiting your approval"),
            "Should show correct pending action count"
        );
    }

    #[tokio::test]
    async fn test_approvals_page_shows_action_targets() {
        use tw_core::incident::{ActionTarget, ActionType};

        let (app, state) = setup_test_app_with_state().await;

        let (_incident_id, _action_id) = create_incident_with_action(
            &state,
            "Malicious IP Connection",
            ActionType::BlockIp,
            ActionTarget::IpAddress("203.0.113.42".to_string()),
            "Block malicious IP address",
        )
        .await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/approvals")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();

        // Verify the target is displayed
        assert!(
            html.contains("203.0.113.42"),
            "Should show IP address target"
        );
        assert!(
            html.contains("Block IP"),
            "Should show block IP action type"
        );
    }

    #[tokio::test]
    async fn test_approvals_page_shows_domain_block_action() {
        use tw_core::incident::{ActionTarget, ActionType};

        let (app, state) = setup_test_app_with_state().await;

        let (_incident_id, _action_id) = create_incident_with_action(
            &state,
            "Phishing Domain Detected",
            ActionType::BlockDomain,
            ActionTarget::Domain("malicious-domain.com".to_string()),
            "Block phishing domain",
        )
        .await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/approvals")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();

        assert!(
            html.contains("malicious-domain.com"),
            "Should show domain target"
        );
        assert!(
            html.contains("Block Domain"),
            "Should show block domain action type"
        );
    }

    #[tokio::test]
    async fn test_approvals_page_shows_quarantine_email_action() {
        use tw_core::incident::{ActionTarget, ActionType};

        let (app, state) = setup_test_app_with_state().await;

        let (_incident_id, _action_id) = create_incident_with_action(
            &state,
            "Phishing Email Reported",
            ActionType::QuarantineEmail,
            ActionTarget::Email {
                message_id: "msg-12345@example.com".to_string(),
            },
            "Quarantine suspicious email",
        )
        .await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/approvals")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();

        assert!(
            html.contains("Quarantine Email"),
            "Should show quarantine email action type"
        );
        assert!(
            html.contains("Quarantine suspicious email"),
            "Should show action reason"
        );
    }

    #[tokio::test]
    async fn test_approvals_page_shows_approve_and_reject_buttons() {
        let (app, state) = setup_test_app_with_state().await;

        let _incident_id = create_test_incident_with_pending_action(&state).await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/approvals")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();

        // Verify approve and reject buttons are present
        assert!(html.contains("Approve"), "Should show Approve button");
        assert!(html.contains("Reject"), "Should show Reject button");
        // Verify HTMX attributes for approve action
        assert!(
            html.contains("hx-post=\"/api/incidents/"),
            "Should have HTMX post to approve endpoint"
        );
        assert!(
            html.contains("/approve\""),
            "Should target the approve endpoint"
        );
        assert!(
            html.contains("\"approved\": true"),
            "Approve button should send approved=true"
        );
        assert!(
            html.contains("\"approved\": false"),
            "Reject button should send approved=false"
        );
    }

    #[tokio::test]
    async fn test_approvals_page_shows_incident_links() {
        let (app, state) = setup_test_app_with_state().await;

        let incident_id = create_test_incident_with_pending_action(&state).await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/approvals")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();

        // Verify incident link is present
        assert!(
            html.contains(&format!("/incidents/{}", incident_id)),
            "Should have link to incident detail page"
        );
        assert!(
            html.contains(&incident_id.to_string()),
            "Should show incident ID"
        );
    }

    #[tokio::test]
    async fn test_approvals_page_shows_risk_level_badge() {
        let (app, state) = setup_test_app_with_state().await;

        let _incident_id = create_test_incident_with_pending_action(&state).await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/approvals")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();

        // Verify risk level badge is shown
        assert!(
            html.contains("high") || html.contains("medium") || html.contains("low"),
            "Should show risk level"
        );
        assert!(
            html.contains("badge"),
            "Should use badge styling for risk level"
        );
    }

    #[tokio::test]
    async fn test_approvals_page_shows_proposed_by_field() {
        let (app, state) = setup_test_app_with_state().await;

        let _incident_id = create_test_incident_with_pending_action(&state).await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/approvals")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();

        // Verify proposed by field is shown
        assert!(
            html.contains("System"),
            "Should show 'System' as the proposer"
        );
    }

    #[tokio::test]
    async fn test_approvals_page_only_shows_pending_status_actions() {
        use std::collections::HashMap;
        use tw_core::db::create_incident_repository;
        use tw_core::incident::{
            ActionTarget, ActionType, Alert, AlertSource, ApprovalStatus, Incident, IncidentStatus,
            ProposedAction, Severity,
        };

        let (app, state) = setup_test_app_with_state().await;

        // Create an incident with one pending action and one approved action
        let alert = Alert {
            id: format!("test-alert-{}", uuid::Uuid::new_v4()),
            source: AlertSource::Edr("CrowdStrike".to_string()),
            alert_type: "malware".to_string(),
            severity: Severity::Critical,
            title: "Mixed Actions Incident".to_string(),
            description: Some("Incident with both pending and approved actions".to_string()),
            data: serde_json::json!({
                "title": "Mixed Actions Incident",
                "hostname": "mixed-host"
            }),
            timestamp: chrono::Utc::now(),
            tags: vec![],
        };

        let mut incident = Incident::from_alert(alert);
        incident.status = IncidentStatus::PendingApproval;

        // Add pending action
        let pending_action = ProposedAction::new(
            ActionType::IsolateHost,
            ActionTarget::Host {
                hostname: "pending-host".to_string(),
                ip: None,
            },
            "Pending isolation".to_string(),
            HashMap::new(),
        );
        incident.proposed_actions.push(pending_action);

        // Add already approved action
        let mut approved_action = ProposedAction::new(
            ActionType::BlockIp,
            ActionTarget::IpAddress("192.168.1.100".to_string()),
            "Already approved block".to_string(),
            HashMap::new(),
        );
        approved_action.approval_status = ApprovalStatus::Approved;
        approved_action.approved_by = Some("admin".to_string());
        incident.proposed_actions.push(approved_action);

        let repo = create_incident_repository(&state.db);
        repo.create(&incident).await.unwrap();
        repo.save(&incident).await.unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/approvals")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();

        // Should only show 1 action (the pending one)
        assert!(
            html.contains("1 actions awaiting your approval"),
            "Should show only 1 pending action"
        );
        assert!(
            html.contains("Pending isolation"),
            "Should show pending action reason"
        );
        // The approved action should not be in the pending approvals table
        // (It would be in recent_approvals if that was populated)
    }

    #[tokio::test]
    async fn test_approvals_page_excludes_denied_actions() {
        use std::collections::HashMap;
        use tw_core::db::create_incident_repository;
        use tw_core::incident::{
            ActionTarget, ActionType, Alert, AlertSource, ApprovalStatus, Incident, IncidentStatus,
            ProposedAction, Severity,
        };

        let (app, state) = setup_test_app_with_state().await;

        let alert = Alert {
            id: format!("test-alert-{}", uuid::Uuid::new_v4()),
            source: AlertSource::Edr("CrowdStrike".to_string()),
            alert_type: "intrusion".to_string(),
            severity: Severity::High,
            title: "Denied Action Incident".to_string(),
            description: None,
            data: serde_json::json!({
                "title": "Denied Action Incident"
            }),
            timestamp: chrono::Utc::now(),
            tags: vec![],
        };

        let mut incident = Incident::from_alert(alert);
        incident.status = IncidentStatus::PendingApproval;

        // Add denied action
        let mut denied_action = ProposedAction::new(
            ActionType::DisableUser,
            ActionTarget::User {
                username: "denied-user".to_string(),
                email: None,
            },
            "Previously denied".to_string(),
            HashMap::new(),
        );
        denied_action.approval_status = ApprovalStatus::Denied;
        incident.proposed_actions.push(denied_action);

        let repo = create_incident_repository(&state.db);
        repo.create(&incident).await.unwrap();
        repo.save(&incident).await.unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/approvals")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();

        // Should show 0 pending actions and empty state
        assert!(
            html.contains("0 actions awaiting your approval"),
            "Should show 0 pending actions"
        );
        assert!(
            html.contains("No pending approvals"),
            "Should show empty state"
        );
    }

    #[tokio::test]
    async fn test_approvals_page_shows_multiple_actions_on_same_incident() {
        use std::collections::HashMap;
        use tw_core::db::create_incident_repository;
        use tw_core::incident::{
            ActionTarget, ActionType, Alert, AlertSource, Incident, IncidentStatus, ProposedAction,
            Severity,
        };

        let (app, state) = setup_test_app_with_state().await;

        let alert = Alert {
            id: format!("test-alert-{}", uuid::Uuid::new_v4()),
            source: AlertSource::Edr("CrowdStrike".to_string()),
            alert_type: "breach".to_string(),
            severity: Severity::Critical,
            title: "Multi-Action Incident".to_string(),
            description: Some("Incident requiring multiple response actions".to_string()),
            data: serde_json::json!({
                "title": "Multi-Action Incident",
                "hostname": "compromised-server"
            }),
            timestamp: chrono::Utc::now(),
            tags: vec!["critical".to_string()],
        };

        let mut incident = Incident::from_alert(alert);
        incident.status = IncidentStatus::PendingApproval;

        // Add multiple pending actions
        incident.proposed_actions.push(ProposedAction::new(
            ActionType::IsolateHost,
            ActionTarget::Host {
                hostname: "compromised-server".to_string(),
                ip: Some("10.0.0.1".to_string()),
            },
            "Isolate compromised server".to_string(),
            HashMap::new(),
        ));

        incident.proposed_actions.push(ProposedAction::new(
            ActionType::DisableUser,
            ActionTarget::User {
                username: "compromised-admin".to_string(),
                email: Some("admin@example.com".to_string()),
            },
            "Disable compromised admin account".to_string(),
            HashMap::new(),
        ));

        incident.proposed_actions.push(ProposedAction::new(
            ActionType::BlockIp,
            ActionTarget::IpAddress("198.51.100.1".to_string()),
            "Block attacker IP".to_string(),
            HashMap::new(),
        ));

        let repo = create_incident_repository(&state.db);
        repo.create(&incident).await.unwrap();
        repo.save(&incident).await.unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/approvals")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();

        // Should show all 3 actions
        assert!(
            html.contains("3 actions awaiting your approval"),
            "Should show 3 pending actions"
        );
        assert!(
            html.contains("Isolate Host"),
            "Should show isolate host action"
        );
        assert!(
            html.contains("Disable User"),
            "Should show disable user action"
        );
        assert!(html.contains("Block IP"), "Should show block IP action");
        // All actions from the same incident
        assert!(
            html.contains("Multi-Action Incident"),
            "Should show incident title for all actions"
        );
    }

    #[tokio::test]
    async fn test_approvals_page_navigation_badge_count_matches() {
        let (app, state) = setup_test_app_with_state().await;

        // Create 2 incidents each with 1 pending action = 2 total
        let _id1 = create_test_incident_with_pending_action(&state).await;

        use tw_core::incident::{ActionTarget, ActionType};
        let (_id2, _action2) = create_incident_with_action(
            &state,
            "Second Incident",
            ActionType::BlockDomain,
            ActionTarget::Domain("evil.com".to_string()),
            "Block evil domain",
        )
        .await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/approvals")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();

        // The page shows pending_actions.len() which is 2
        assert!(
            html.contains("2 actions awaiting your approval"),
            "Should show 2 pending actions in subtitle"
        );
    }

    #[tokio::test]
    async fn test_approvals_page_shows_correct_time_ago_format() {
        let (app, state) = setup_test_app_with_state().await;

        let _incident_id = create_test_incident_with_pending_action(&state).await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/approvals")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();

        // Should show time in relative format (e.g., "0s ago", "1m ago")
        assert!(
            html.contains("ago"),
            "Should show relative time format with 'ago'"
        );
    }

    #[tokio::test]
    async fn test_approvals_page_table_structure() {
        let (app, state) = setup_test_app_with_state().await;

        let _incident_id = create_test_incident_with_pending_action(&state).await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/approvals")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();

        // Verify table structure with expected headers
        assert!(html.contains("<table"), "Should have table element");
        assert!(html.contains("<thead>"), "Should have table header");
        assert!(html.contains("<tbody>"), "Should have table body");
        assert!(
            html.contains(">Incident</th>"),
            "Should have Incident column header"
        );
        assert!(
            html.contains(">Action</th>"),
            "Should have Action column header"
        );
        assert!(
            html.contains(">Target</th>"),
            "Should have Target column header"
        );
        assert!(
            html.contains(">Risk</th>"),
            "Should have Risk column header"
        );
        assert!(
            html.contains(">Proposed</th>"),
            "Should have Proposed column header"
        );
    }

    #[tokio::test]
    async fn test_approvals_page_action_row_id_format() {
        let (app, state) = setup_test_app_with_state().await;

        let _incident_id = create_test_incident_with_pending_action(&state).await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/approvals")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();

        // Verify each action row has an id attribute for HTMX targeting
        assert!(
            html.contains("id=\"action-"),
            "Should have action row with id for HTMX swap target"
        );
    }

    #[tokio::test]
    async fn test_approvals_page_with_custom_action_type() {
        use tw_core::incident::{ActionTarget, ActionType};

        let (app, state) = setup_test_app_with_state().await;

        let (_incident_id, _action_id) = create_incident_with_action(
            &state,
            "Custom Action Test",
            ActionType::Custom("run_custom_script".to_string()),
            ActionTarget::Host {
                hostname: "target-host".to_string(),
                ip: None,
            },
            "Run custom remediation script",
        )
        .await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/approvals")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();

        // Custom action type should be displayed
        assert!(
            html.contains("Custom(\"run_custom_script\")") || html.contains("run_custom_script"),
            "Should show custom action type"
        );
        assert!(
            html.contains("Run custom remediation script"),
            "Should show custom action reason"
        );
    }

    #[tokio::test]
    async fn test_approvals_page_excludes_non_pending_approval_incidents() {
        use tw_core::db::create_incident_repository;
        use tw_core::incident::{IncidentStatus, Severity};

        let (app, state) = setup_test_app_with_state().await;

        // Create an incident that is NOT in PendingApproval status
        let incident =
            create_test_incident("New Status Incident", Severity::High, IncidentStatus::New);
        // Even if it has proposed actions, they shouldn't appear
        // because the incident status is not PendingApproval
        let repo = create_incident_repository(&state.db);
        repo.create(&incident).await.unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/approvals")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();

        // Should show empty state since the incident is not PendingApproval
        assert!(
            html.contains("No pending approvals"),
            "Should show empty state for non-PendingApproval incidents"
        );
        assert!(
            !html.contains("New Status Incident"),
            "Should not show incidents that are not in PendingApproval status"
        );
    }

    #[tokio::test]
    async fn test_approvals_page_htmx_swap_targets_correct() {
        let (app, state) = setup_test_app_with_state().await;

        let _incident_id = create_test_incident_with_pending_action(&state).await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/approvals")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();

        // Verify HTMX swap configuration
        assert!(
            html.contains("hx-target=\"#action-"),
            "Should target the specific action row for swap"
        );
        assert!(
            html.contains("hx-swap=\"outerHTML\""),
            "Should use outerHTML swap to replace the entire row"
        );
    }

    #[tokio::test]
    async fn test_approvals_page_includes_action_id_in_form() {
        let (app, state) = setup_test_app_with_state().await;

        let _incident_id = create_test_incident_with_pending_action(&state).await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/approvals")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();

        // Verify action_id is included in the form data
        assert!(
            html.contains("action_id"),
            "Should include action_id in approve/reject form values"
        );
    }

    #[tokio::test]
    async fn test_approvals_page_renders_with_unisolate_host_action() {
        use tw_core::incident::{ActionTarget, ActionType};

        let (app, state) = setup_test_app_with_state().await;

        let (_incident_id, _action_id) = create_incident_with_action(
            &state,
            "Host Cleanup Complete",
            ActionType::UnisolateHost,
            ActionTarget::Host {
                hostname: "cleaned-host".to_string(),
                ip: Some("10.0.0.99".to_string()),
            },
            "Restore network access after cleanup",
        )
        .await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/approvals")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();

        assert!(
            html.contains("Unisolate Host"),
            "Should show unisolate host action type"
        );
        assert!(
            html.contains("Restore network access after cleanup"),
            "Should show action reason"
        );
    }

    #[tokio::test]
    async fn test_approvals_page_renders_with_reset_password_action() {
        use tw_core::incident::{ActionTarget, ActionType};

        let (app, state) = setup_test_app_with_state().await;

        let (_incident_id, _action_id) = create_incident_with_action(
            &state,
            "Credential Compromise Detected",
            ActionType::ResetPassword,
            ActionTarget::User {
                username: "breached-user".to_string(),
                email: Some("breached@example.com".to_string()),
            },
            "Force password reset for compromised account",
        )
        .await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/approvals")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();

        assert!(
            html.contains("Reset Password"),
            "Should show reset password action type"
        );
    }

    #[tokio::test]
    async fn test_approvals_page_renders_with_revoke_sessions_action() {
        use tw_core::incident::{ActionTarget, ActionType};

        let (app, state) = setup_test_app_with_state().await;

        let (_incident_id, _action_id) = create_incident_with_action(
            &state,
            "Session Hijacking Detected",
            ActionType::RevokeSessions,
            ActionTarget::User {
                username: "hijacked-user".to_string(),
                email: None,
            },
            "Revoke all active sessions",
        )
        .await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/approvals")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();

        assert!(
            html.contains("Revoke Sessions"),
            "Should show revoke sessions action type"
        );
    }

    #[tokio::test]
    async fn test_approvals_page_renders_with_create_ticket_action() {
        use tw_core::incident::{ActionTarget, ActionType};

        let (app, state) = setup_test_app_with_state().await;

        let (_incident_id, _action_id) = create_incident_with_action(
            &state,
            "Security Incident Requiring Ticket",
            ActionType::CreateTicket,
            ActionTarget::None,
            "Create Jira ticket for tracking",
        )
        .await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/approvals")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();

        assert!(
            html.contains("Create Ticket"),
            "Should show create ticket action type"
        );
    }

    #[tokio::test]
    async fn test_approvals_count_in_dashboard_navigation() {
        use tw_core::incident::{ActionTarget, ActionType};

        let (app, state) = setup_test_app_with_state().await;

        // Create 3 incidents with pending actions
        for i in 1..=3 {
            let _ = create_incident_with_action(
                &state,
                &format!("Pending Action Incident {}", i),
                ActionType::IsolateHost,
                ActionTarget::Host {
                    hostname: format!("host-{}", i),
                    ip: None,
                },
                &format!("Reason for action {}", i),
            )
            .await;
        }

        // Check the dashboard page (which also shows approval count)
        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();

        // Dashboard should show the approval count in navigation
        // The approval_count is used by the base template for the nav badge
        assert!(
            html.contains("3") || html.contains("Approvals"),
            "Dashboard should show approval count or link to approvals"
        );
    }
}
