//! Settings management endpoints.

use axum::{
    extract::State,
    response::{IntoResponse, Response},
    routing::get,
    Form, Json, Router,
};
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::state::AppState;
use tw_core::db::{create_settings_repository, GeneralSettings, RateLimits, SettingsRepository};

/// Creates settings routes.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/general",
            get(get_general_settings).post(save_general_settings),
        )
        .route("/rate-limits", get(get_rate_limits).post(save_rate_limits))
}

/// Form data for general settings (matches HTML form fields).
#[derive(Debug, Deserialize)]
pub struct GeneralSettingsForm {
    pub org_name: String,
    pub timezone: String,
    pub mode: String,
}

/// Form data for rate limits (matches HTML form fields).
#[derive(Debug, Deserialize)]
pub struct RateLimitsForm {
    pub isolate_host_hour: u32,
    pub disable_user_hour: u32,
    pub block_ip_hour: u32,
}

/// Response wrapper for general settings.
#[derive(Debug, Serialize)]
pub struct GeneralSettingsResponse {
    pub org_name: String,
    pub timezone: String,
    pub mode: String,
}

/// Response wrapper for rate limits.
#[derive(Debug, Serialize)]
pub struct RateLimitsResponse {
    pub isolate_host_hour: u32,
    pub disable_user_hour: u32,
    pub block_ip_hour: u32,
}

/// Get general settings.
async fn get_general_settings(
    State(state): State<AppState>,
) -> Result<Json<GeneralSettingsResponse>, ApiError> {
    let repo: Box<dyn SettingsRepository> = create_settings_repository(&state.db);

    let settings = repo.get_general().await?;

    Ok(Json(GeneralSettingsResponse {
        org_name: settings.org_name,
        timezone: settings.timezone,
        mode: settings.mode,
    }))
}

/// Save general settings.
async fn save_general_settings(
    State(state): State<AppState>,
    Form(form): Form<GeneralSettingsForm>,
) -> Result<Response, ApiError> {
    let repo: Box<dyn SettingsRepository> = create_settings_repository(&state.db);

    let settings = GeneralSettings {
        org_name: form.org_name,
        timezone: form.timezone,
        mode: form.mode,
    };

    repo.save_general(&settings).await?;

    // Return HX-Trigger header for toast notification
    let trigger_json = serde_json::json!({
        "showToast": {
            "type": "success",
            "title": "Settings Saved",
            "message": "General settings have been updated."
        }
    });

    Ok((
        [(
            axum::http::header::HeaderName::from_static("hx-trigger"),
            trigger_json.to_string(),
        )],
        "",
    )
        .into_response())
}

/// Get rate limit settings.
async fn get_rate_limits(
    State(state): State<AppState>,
) -> Result<Json<RateLimitsResponse>, ApiError> {
    let repo: Box<dyn SettingsRepository> = create_settings_repository(&state.db);

    let limits = repo.get_rate_limits().await?;

    Ok(Json(RateLimitsResponse {
        isolate_host_hour: limits.isolate_host_hour,
        disable_user_hour: limits.disable_user_hour,
        block_ip_hour: limits.block_ip_hour,
    }))
}

/// Save rate limit settings.
async fn save_rate_limits(
    State(state): State<AppState>,
    Form(form): Form<RateLimitsForm>,
) -> Result<Response, ApiError> {
    let repo: Box<dyn SettingsRepository> = create_settings_repository(&state.db);

    let limits = RateLimits {
        isolate_host_hour: form.isolate_host_hour,
        disable_user_hour: form.disable_user_hour,
        block_ip_hour: form.block_ip_hour,
    };

    repo.save_rate_limits(&limits).await?;

    // Return HX-Trigger header for toast notification
    let trigger_json = serde_json::json!({
        "showToast": {
            "type": "success",
            "title": "Rate Limits Saved",
            "message": "Rate limit settings have been updated."
        }
    });

    Ok((
        [(
            axum::http::header::HeaderName::from_static("hx-trigger"),
            trigger_json.to_string(),
        )],
        "",
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_general_settings_form_deserialization() {
        let form_data = "org_name=Acme&timezone=UTC&mode=supervised";
        let form: GeneralSettingsForm = serde_urlencoded::from_str(form_data).unwrap();
        assert_eq!(form.org_name, "Acme");
        assert_eq!(form.timezone, "UTC");
        assert_eq!(form.mode, "supervised");
    }

    #[test]
    fn test_rate_limits_form_deserialization() {
        let form_data = "isolate_host_hour=10&disable_user_hour=5&block_ip_hour=20";
        let form: RateLimitsForm = serde_urlencoded::from_str(form_data).unwrap();
        assert_eq!(form.isolate_host_hour, 10);
        assert_eq!(form.disable_user_hour, 5);
        assert_eq!(form.block_ip_hour, 20);
    }
}
