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
#[derive(Debug, Serialize, Deserialize)]
pub struct GeneralSettingsResponse {
    pub org_name: String,
    pub timezone: String,
    pub mode: String,
}

/// Response wrapper for rate limits.
#[derive(Debug, Serialize, Deserialize)]
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
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;
    use tw_core::db::DbPool;
    use tw_core::EventBus;

    // ==================================================
    // Form Deserialization Tests
    // ==================================================

    #[test]
    fn test_general_settings_form_deserialization() {
        let form_data = "org_name=Acme&timezone=UTC&mode=supervised";
        let form: GeneralSettingsForm = serde_urlencoded::from_str(form_data).unwrap();
        assert_eq!(form.org_name, "Acme");
        assert_eq!(form.timezone, "UTC");
        assert_eq!(form.mode, "supervised");
    }

    #[test]
    fn test_general_settings_form_with_special_characters() {
        let form_data = "org_name=Acme%20Corp&timezone=America%2FNew_York&mode=autonomous";
        let form: GeneralSettingsForm = serde_urlencoded::from_str(form_data).unwrap();
        assert_eq!(form.org_name, "Acme Corp");
        assert_eq!(form.timezone, "America/New_York");
        assert_eq!(form.mode, "autonomous");
    }

    #[test]
    fn test_general_settings_form_with_empty_values() {
        let form_data = "org_name=&timezone=&mode=";
        let form: GeneralSettingsForm = serde_urlencoded::from_str(form_data).unwrap();
        assert_eq!(form.org_name, "");
        assert_eq!(form.timezone, "");
        assert_eq!(form.mode, "");
    }

    #[test]
    fn test_rate_limits_form_deserialization() {
        let form_data = "isolate_host_hour=10&disable_user_hour=5&block_ip_hour=20";
        let form: RateLimitsForm = serde_urlencoded::from_str(form_data).unwrap();
        assert_eq!(form.isolate_host_hour, 10);
        assert_eq!(form.disable_user_hour, 5);
        assert_eq!(form.block_ip_hour, 20);
    }

    #[test]
    fn test_rate_limits_form_with_zero_values() {
        let form_data = "isolate_host_hour=0&disable_user_hour=0&block_ip_hour=0";
        let form: RateLimitsForm = serde_urlencoded::from_str(form_data).unwrap();
        assert_eq!(form.isolate_host_hour, 0);
        assert_eq!(form.disable_user_hour, 0);
        assert_eq!(form.block_ip_hour, 0);
    }

    #[test]
    fn test_rate_limits_form_with_large_values() {
        let form_data = "isolate_host_hour=1000&disable_user_hour=500&block_ip_hour=2000";
        let form: RateLimitsForm = serde_urlencoded::from_str(form_data).unwrap();
        assert_eq!(form.isolate_host_hour, 1000);
        assert_eq!(form.disable_user_hour, 500);
        assert_eq!(form.block_ip_hour, 2000);
    }

    // ==================================================
    // Response Serialization Tests
    // ==================================================

    #[test]
    fn test_general_settings_response_serialization() {
        let response = GeneralSettingsResponse {
            org_name: "Test Org".to_string(),
            timezone: "UTC".to_string(),
            mode: "supervised".to_string(),
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"org_name\":\"Test Org\""));
        assert!(json.contains("\"timezone\":\"UTC\""));
        assert!(json.contains("\"mode\":\"supervised\""));
    }

    #[test]
    fn test_rate_limits_response_serialization() {
        let response = RateLimitsResponse {
            isolate_host_hour: 15,
            disable_user_hour: 10,
            block_ip_hour: 25,
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"isolate_host_hour\":15"));
        assert!(json.contains("\"disable_user_hour\":10"));
        assert!(json.contains("\"block_ip_hour\":25"));
    }

    // ==================================================
    // Helper Functions for Integration Tests
    // ==================================================

    /// Creates an in-memory SQLite database pool with the settings schema.
    async fn create_test_db() -> DbPool {
        let db_url = format!(
            "sqlite:file:test_settings_{}?mode=memory&cache=shared",
            uuid::Uuid::new_v4()
        );

        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect(&db_url)
            .await
            .expect("Failed to create test database pool");

        // Create the settings table manually (not using migrations)
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            "#,
        )
        .execute(&pool)
        .await
        .expect("Failed to create settings table");

        DbPool::Sqlite(pool)
    }

    /// Creates an AppState with a test database.
    async fn create_test_state() -> AppState {
        let db = create_test_db().await;
        let event_bus = EventBus::new(100);
        AppState::new(db, event_bus)
    }

    /// Creates a test router with the settings routes.
    fn create_test_router(state: AppState) -> Router<()> {
        Router::new().nest("/settings", routes()).with_state(state)
    }

    // ==================================================
    // GET /settings/general Tests
    // ==================================================

    #[tokio::test]
    async fn test_get_general_settings_returns_defaults_when_empty() {
        let state = create_test_state().await;
        let app = create_test_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/settings/general")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let settings: GeneralSettingsResponse = serde_json::from_slice(&body).unwrap();

        // Default values should be empty strings
        assert_eq!(settings.org_name, "");
        assert_eq!(settings.timezone, "");
        assert_eq!(settings.mode, "");
    }

    #[tokio::test]
    async fn test_get_general_settings_returns_saved_values() {
        let state = create_test_state().await;

        // Pre-populate the database with settings
        let repo = create_settings_repository(&state.db);
        let settings = GeneralSettings {
            org_name: "Security Team".to_string(),
            timezone: "America/Los_Angeles".to_string(),
            mode: "autonomous".to_string(),
        };
        repo.save_general(&settings).await.unwrap();

        let app = create_test_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/settings/general")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let result: GeneralSettingsResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(result.org_name, "Security Team");
        assert_eq!(result.timezone, "America/Los_Angeles");
        assert_eq!(result.mode, "autonomous");
    }

    #[tokio::test]
    async fn test_get_general_settings_returns_json_content_type() {
        let state = create_test_state().await;
        let app = create_test_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/settings/general")
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
            content_type.to_str().unwrap().contains("application/json"),
            "Response should have JSON content type"
        );
    }

    // ==================================================
    // POST /settings/general Tests
    // ==================================================

    #[tokio::test]
    async fn test_save_general_settings_success() {
        let state = create_test_state().await;
        let app = create_test_router(state.clone());

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/settings/general")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(
                        "org_name=New%20Org&timezone=Europe%2FLondon&mode=assisted",
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Verify HX-Trigger header is present for HTMX toast notification
        let hx_trigger = response.headers().get("hx-trigger");
        assert!(hx_trigger.is_some(), "HX-Trigger header should be present");

        let trigger_value = hx_trigger.unwrap().to_str().unwrap();
        assert!(
            trigger_value.contains("showToast"),
            "HX-Trigger should contain showToast"
        );
        assert!(
            trigger_value.contains("success"),
            "Toast should be of type success"
        );

        // Verify settings were actually saved
        let repo = create_settings_repository(&state.db);
        let saved = repo.get_general().await.unwrap();
        assert_eq!(saved.org_name, "New Org");
        assert_eq!(saved.timezone, "Europe/London");
        assert_eq!(saved.mode, "assisted");
    }

    #[tokio::test]
    async fn test_save_general_settings_updates_existing() {
        let state = create_test_state().await;

        // Save initial settings
        let repo = create_settings_repository(&state.db);
        let initial = GeneralSettings {
            org_name: "Old Org".to_string(),
            timezone: "UTC".to_string(),
            mode: "supervised".to_string(),
        };
        repo.save_general(&initial).await.unwrap();

        let app = create_test_router(state.clone());

        // Update settings via handler
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/settings/general")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(
                        "org_name=Updated%20Org&timezone=Asia%2FTokyo&mode=autonomous",
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Verify settings were updated
        let updated = repo.get_general().await.unwrap();
        assert_eq!(updated.org_name, "Updated Org");
        assert_eq!(updated.timezone, "Asia/Tokyo");
        assert_eq!(updated.mode, "autonomous");
    }

    #[tokio::test]
    async fn test_save_general_settings_with_empty_values() {
        let state = create_test_state().await;
        let app = create_test_router(state.clone());

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/settings/general")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("org_name=&timezone=&mode="))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Verify empty values were saved
        let repo = create_settings_repository(&state.db);
        let saved = repo.get_general().await.unwrap();
        assert_eq!(saved.org_name, "");
        assert_eq!(saved.timezone, "");
        assert_eq!(saved.mode, "");
    }

    #[tokio::test]
    async fn test_save_general_settings_with_unicode() {
        let state = create_test_state().await;
        let app = create_test_router(state.clone());

        // URL-encoded unicode characters
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/settings/general")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(
                        "org_name=%E3%82%BB%E3%82%AD%E3%83%A5%E3%83%AA%E3%83%86%E3%82%A3%E3%83%BC&timezone=Asia%2FTokyo&mode=supervised",
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Verify unicode was saved correctly
        let repo = create_settings_repository(&state.db);
        let saved = repo.get_general().await.unwrap();
        assert_eq!(
            saved.org_name,
            "\u{30BB}\u{30AD}\u{30E5}\u{30EA}\u{30C6}\u{30A3}\u{30FC}"
        ); // "Security" in Japanese katakana
    }

    // ==================================================
    // GET /settings/rate-limits Tests
    // ==================================================

    #[tokio::test]
    async fn test_get_rate_limits_returns_defaults_when_empty() {
        let state = create_test_state().await;
        let app = create_test_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/settings/rate-limits")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let limits: RateLimitsResponse = serde_json::from_slice(&body).unwrap();

        // Default values should be 0
        assert_eq!(limits.isolate_host_hour, 0);
        assert_eq!(limits.disable_user_hour, 0);
        assert_eq!(limits.block_ip_hour, 0);
    }

    #[tokio::test]
    async fn test_get_rate_limits_returns_saved_values() {
        let state = create_test_state().await;

        // Pre-populate the database with rate limits
        let repo = create_settings_repository(&state.db);
        let limits = RateLimits {
            isolate_host_hour: 50,
            disable_user_hour: 25,
            block_ip_hour: 100,
        };
        repo.save_rate_limits(&limits).await.unwrap();

        let app = create_test_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/settings/rate-limits")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let result: RateLimitsResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(result.isolate_host_hour, 50);
        assert_eq!(result.disable_user_hour, 25);
        assert_eq!(result.block_ip_hour, 100);
    }

    #[tokio::test]
    async fn test_get_rate_limits_returns_json_content_type() {
        let state = create_test_state().await;
        let app = create_test_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/settings/rate-limits")
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
            content_type.to_str().unwrap().contains("application/json"),
            "Response should have JSON content type"
        );
    }

    // ==================================================
    // POST /settings/rate-limits Tests
    // ==================================================

    #[tokio::test]
    async fn test_save_rate_limits_success() {
        let state = create_test_state().await;
        let app = create_test_router(state.clone());

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/settings/rate-limits")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(
                        "isolate_host_hour=30&disable_user_hour=15&block_ip_hour=60",
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Verify HX-Trigger header is present for HTMX toast notification
        let hx_trigger = response.headers().get("hx-trigger");
        assert!(hx_trigger.is_some(), "HX-Trigger header should be present");

        let trigger_value = hx_trigger.unwrap().to_str().unwrap();
        assert!(
            trigger_value.contains("showToast"),
            "HX-Trigger should contain showToast"
        );
        assert!(
            trigger_value.contains("Rate Limits Saved"),
            "Toast should mention Rate Limits Saved"
        );

        // Verify settings were actually saved
        let repo = create_settings_repository(&state.db);
        let saved = repo.get_rate_limits().await.unwrap();
        assert_eq!(saved.isolate_host_hour, 30);
        assert_eq!(saved.disable_user_hour, 15);
        assert_eq!(saved.block_ip_hour, 60);
    }

    #[tokio::test]
    async fn test_save_rate_limits_updates_existing() {
        let state = create_test_state().await;

        // Save initial rate limits
        let repo = create_settings_repository(&state.db);
        let initial = RateLimits {
            isolate_host_hour: 10,
            disable_user_hour: 5,
            block_ip_hour: 20,
        };
        repo.save_rate_limits(&initial).await.unwrap();

        let app = create_test_router(state.clone());

        // Update rate limits via handler
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/settings/rate-limits")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(
                        "isolate_host_hour=100&disable_user_hour=50&block_ip_hour=200",
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Verify rate limits were updated
        let updated = repo.get_rate_limits().await.unwrap();
        assert_eq!(updated.isolate_host_hour, 100);
        assert_eq!(updated.disable_user_hour, 50);
        assert_eq!(updated.block_ip_hour, 200);
    }

    #[tokio::test]
    async fn test_save_rate_limits_with_zero_values() {
        let state = create_test_state().await;
        let app = create_test_router(state.clone());

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/settings/rate-limits")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(
                        "isolate_host_hour=0&disable_user_hour=0&block_ip_hour=0",
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Verify zero values were saved
        let repo = create_settings_repository(&state.db);
        let saved = repo.get_rate_limits().await.unwrap();
        assert_eq!(saved.isolate_host_hour, 0);
        assert_eq!(saved.disable_user_hour, 0);
        assert_eq!(saved.block_ip_hour, 0);
    }

    #[tokio::test]
    async fn test_save_rate_limits_with_max_u32_values() {
        let state = create_test_state().await;
        let app = create_test_router(state.clone());

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/settings/rate-limits")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(format!(
                        "isolate_host_hour={}&disable_user_hour={}&block_ip_hour={}",
                        u32::MAX,
                        u32::MAX,
                        u32::MAX
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Verify max values were saved
        let repo = create_settings_repository(&state.db);
        let saved = repo.get_rate_limits().await.unwrap();
        assert_eq!(saved.isolate_host_hour, u32::MAX);
        assert_eq!(saved.disable_user_hour, u32::MAX);
        assert_eq!(saved.block_ip_hour, u32::MAX);
    }

    // ==================================================
    // Error Cases Tests
    // ==================================================

    #[tokio::test]
    async fn test_save_general_settings_missing_fields_returns_error() {
        let state = create_test_state().await;
        let app = create_test_router(state);

        // Missing 'mode' field
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/settings/general")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("org_name=Test&timezone=UTC"))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should return an error status (422 Unprocessable Entity)
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn test_save_rate_limits_missing_fields_returns_error() {
        let state = create_test_state().await;
        let app = create_test_router(state);

        // Missing 'block_ip_hour' field
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/settings/rate-limits")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("isolate_host_hour=10&disable_user_hour=5"))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should return an error status (422 Unprocessable Entity)
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn test_save_rate_limits_invalid_number_returns_error() {
        let state = create_test_state().await;
        let app = create_test_router(state);

        // Invalid number for isolate_host_hour
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/settings/rate-limits")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(
                        "isolate_host_hour=invalid&disable_user_hour=5&block_ip_hour=10",
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should return an error status (422 Unprocessable Entity)
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn test_save_rate_limits_negative_number_returns_error() {
        let state = create_test_state().await;
        let app = create_test_router(state);

        // Negative number (u32 cannot be negative)
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/settings/rate-limits")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(
                        "isolate_host_hour=-5&disable_user_hour=5&block_ip_hour=10",
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should return an error status (422 Unprocessable Entity)
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    // ==================================================
    // Routes Configuration Tests
    // ==================================================

    #[test]
    fn test_routes_creates_router() {
        // This test verifies that the routes() function creates a valid Router
        let _router: Router<AppState> = routes();
    }

    // ==================================================
    // Concurrent Access Tests
    // ==================================================

    #[tokio::test]
    async fn test_concurrent_settings_updates() {
        let state = create_test_state().await;

        // Spawn multiple tasks that update settings concurrently
        let mut handles = vec![];

        for i in 0..5 {
            let state_clone = state.clone();
            let handle = tokio::spawn(async move {
                let app = create_test_router(state_clone);
                let response = app
                    .oneshot(
                        Request::builder()
                            .method("POST")
                            .uri("/settings/general")
                            .header("content-type", "application/x-www-form-urlencoded")
                            .body(Body::from(format!(
                                "org_name=Org{}&timezone=UTC&mode=supervised",
                                i
                            )))
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                response.status()
            });
            handles.push(handle);
        }

        // All requests should succeed
        for handle in handles {
            let status = handle.await.unwrap();
            assert_eq!(status, StatusCode::OK);
        }

        // Final state should be one of the updates (last writer wins)
        let repo = create_settings_repository(&state.db);
        let saved = repo.get_general().await.unwrap();
        assert!(saved.org_name.starts_with("Org"));
    }

    // ==================================================
    // Round-Trip Tests
    // ==================================================

    #[tokio::test]
    async fn test_general_settings_round_trip() {
        let state = create_test_state().await;

        // Save settings via POST
        let app = create_test_router(state.clone());
        let save_response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/settings/general")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(
                        "org_name=RoundTrip%20Org&timezone=Pacific%2FAuckland&mode=autonomous",
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(save_response.status(), StatusCode::OK);

        // Retrieve settings via GET
        let app = create_test_router(state);
        let get_response = app
            .oneshot(
                Request::builder()
                    .uri("/settings/general")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(get_response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(get_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let result: GeneralSettingsResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(result.org_name, "RoundTrip Org");
        assert_eq!(result.timezone, "Pacific/Auckland");
        assert_eq!(result.mode, "autonomous");
    }

    #[tokio::test]
    async fn test_rate_limits_round_trip() {
        let state = create_test_state().await;

        // Save rate limits via POST
        let app = create_test_router(state.clone());
        let save_response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/settings/rate-limits")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(
                        "isolate_host_hour=42&disable_user_hour=21&block_ip_hour=84",
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(save_response.status(), StatusCode::OK);

        // Retrieve rate limits via GET
        let app = create_test_router(state);
        let get_response = app
            .oneshot(
                Request::builder()
                    .uri("/settings/rate-limits")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(get_response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(get_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let result: RateLimitsResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(result.isolate_host_hour, 42);
        assert_eq!(result.disable_user_hour, 21);
        assert_eq!(result.block_ip_hour, 84);
    }
}
