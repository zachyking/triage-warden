//! Playbook management endpoints.

use axum::{
    extract::{Path, State},
    http::header,
    response::IntoResponse,
    routing::{get, post, put},
    Json, Router,
};
use serde::Deserialize;
use uuid::Uuid;

use crate::auth::{RequireAdmin, RequireAnalyst};
use crate::dto::{
    CreatePlaybookRequest, PlaybookResponse, PlaybookStageDto, PlaybookStepDto,
    UpdatePlaybookRequest,
};
use crate::error::ApiError;
use crate::state::AppState;
use tw_core::db::{create_playbook_repository, PlaybookFilter, PlaybookRepository, PlaybookUpdate};
use tw_core::playbook::{Playbook, PlaybookStage, PlaybookStep};

/// Creates playbook routes.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/", get(list_playbooks).post(create_playbook))
        .route(
            "/:id",
            get(get_playbook)
                .put(update_playbook)
                .delete(delete_playbook),
        )
        .route("/:id/toggle", post(toggle_playbook))
        // Stage management routes
        .route("/:id/stages", post(add_stage))
        .route(
            "/:id/stages/:stage_index",
            put(update_stage).delete(delete_stage),
        )
        // Step management routes
        .route("/:id/stages/:stage_index/steps", post(add_step))
        .route(
            "/:id/stages/:stage_index/steps/:step_index",
            put(update_step).delete(delete_step),
        )
}

/// List all playbooks.
#[utoipa::path(
    get,
    path = "/api/playbooks",
    responses(
        (status = 200, description = "List of playbooks", body = Vec<PlaybookResponse>),
        (status = 500, description = "Internal server error")
    ),
    tag = "Playbooks"
)]
async fn list_playbooks(
    State(state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
) -> Result<Json<Vec<PlaybookResponse>>, ApiError> {
    let repo: Box<dyn PlaybookRepository> = create_playbook_repository(&state.db);

    let filter = PlaybookFilter::default();
    let playbooks: Vec<Playbook> = repo.list(&filter).await?;

    let responses: Vec<PlaybookResponse> =
        playbooks.into_iter().map(playbook_to_response).collect();

    Ok(Json(responses))
}

/// Get a single playbook by ID.
#[utoipa::path(
    get,
    path = "/api/playbooks/{id}",
    params(
        ("id" = Uuid, Path, description = "Playbook ID")
    ),
    responses(
        (status = 200, description = "Playbook details", body = PlaybookResponse),
        (status = 404, description = "Playbook not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "Playbooks"
)]
async fn get_playbook(
    State(state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    Path(id): Path<Uuid>,
) -> Result<Json<PlaybookResponse>, ApiError> {
    let repo: Box<dyn PlaybookRepository> = create_playbook_repository(&state.db);

    let playbook: Playbook = repo
        .get(id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Playbook {} not found", id)))?;

    Ok(Json(playbook_to_response(playbook)))
}

/// Create a new playbook.
#[utoipa::path(
    post,
    path = "/api/playbooks",
    request_body = CreatePlaybookRequest,
    responses(
        (status = 200, description = "Playbook created successfully"),
        (status = 400, description = "Invalid request"),
        (status = 409, description = "Playbook with this name already exists"),
        (status = 500, description = "Internal server error")
    ),
    tag = "Playbooks"
)]
async fn create_playbook(
    State(state): State<AppState>,
    RequireAdmin(_user): RequireAdmin,
    axum::Form(request): axum::Form<CreatePlaybookRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let repo: Box<dyn PlaybookRepository> = create_playbook_repository(&state.db);

    // Check if a playbook with this name already exists
    if let Some(_existing) = repo.get_by_name(&request.name).await? {
        return Err(ApiError::Conflict(format!(
            "Playbook with name '{}' already exists",
            request.name
        )));
    }

    // Build the playbook
    let mut playbook = Playbook::new(&request.name, &request.trigger_type);

    if let Some(description) = &request.description {
        if !description.is_empty() {
            playbook.description = Some(description.clone());
        }
    }

    if let Some(condition) = &request.trigger_condition {
        if !condition.is_empty() {
            playbook.trigger_condition = Some(condition.clone());
        }
    }

    playbook.enabled = request.enabled.unwrap_or(true);

    // Parse stages from JSON if provided
    if let Some(stages_json) = &request.stages {
        if !stages_json.is_empty() {
            let stages: Vec<PlaybookStageDto> = serde_json::from_str(stages_json)
                .map_err(|e| ApiError::BadRequest(format!("Invalid stages JSON: {}", e)))?;
            playbook.stages = stages.into_iter().map(stage_dto_to_stage).collect();
        }
    }

    // Create the playbook
    repo.create(&playbook).await?;

    let trigger = serde_json::json!({
        "showToast": {
            "type": "success",
            "title": "Playbook Created",
            "message": format!("Playbook '{}' has been created successfully.", playbook.name)
        }
    });

    Ok((
        [(
            header::HeaderName::from_static("hx-trigger"),
            trigger.to_string(),
        )],
        "",
    ))
}

/// Update an existing playbook.
#[utoipa::path(
    put,
    path = "/api/playbooks/{id}",
    params(
        ("id" = Uuid, Path, description = "Playbook ID")
    ),
    request_body = UpdatePlaybookRequest,
    responses(
        (status = 200, description = "Playbook updated successfully"),
        (status = 400, description = "Invalid request"),
        (status = 404, description = "Playbook not found"),
        (status = 409, description = "Playbook with this name already exists"),
        (status = 500, description = "Internal server error")
    ),
    tag = "Playbooks"
)]
async fn update_playbook(
    State(state): State<AppState>,
    RequireAdmin(_user): RequireAdmin,
    Path(id): Path<Uuid>,
    axum::Form(request): axum::Form<UpdatePlaybookRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let repo: Box<dyn PlaybookRepository> = create_playbook_repository(&state.db);

    // Verify playbook exists
    let existing: Playbook = repo
        .get(id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Playbook {} not found", id)))?;

    // Check for name conflict if name is being changed
    if let Some(ref new_name) = request.name {
        if new_name != &existing.name {
            if let Some(_conflict) = repo.get_by_name(new_name).await? {
                return Err(ApiError::Conflict(format!(
                    "Playbook with name '{}' already exists",
                    new_name
                )));
            }
        }
    }

    // Build the update
    let mut update = PlaybookUpdate::default();

    if let Some(name) = request.name {
        if !name.is_empty() {
            update.name = Some(name);
        }
    }

    if let Some(description) = request.description {
        update.description = Some(if description.is_empty() {
            None
        } else {
            Some(description)
        });
    }

    if let Some(trigger_type) = request.trigger_type {
        if !trigger_type.is_empty() {
            update.trigger_type = Some(trigger_type);
        }
    }

    if let Some(trigger_condition) = request.trigger_condition {
        update.trigger_condition = Some(if trigger_condition.is_empty() {
            None
        } else {
            Some(trigger_condition)
        });
    }

    if let Some(enabled) = request.enabled {
        update.enabled = Some(enabled);
    }

    // Parse stages from JSON if provided
    if let Some(stages_json) = request.stages {
        if !stages_json.is_empty() {
            let stages: Vec<PlaybookStageDto> = serde_json::from_str(&stages_json)
                .map_err(|e| ApiError::BadRequest(format!("Invalid stages JSON: {}", e)))?;
            update.stages = Some(stages.into_iter().map(stage_dto_to_stage).collect());
        }
    }

    // Apply the update
    let updated = repo.update(id, &update).await?;

    let trigger = serde_json::json!({
        "showToast": {
            "type": "success",
            "title": "Playbook Updated",
            "message": format!("Playbook '{}' has been updated successfully.", updated.name)
        }
    });

    Ok((
        [(
            header::HeaderName::from_static("hx-trigger"),
            trigger.to_string(),
        )],
        "",
    ))
}

/// Delete a playbook.
#[utoipa::path(
    delete,
    path = "/api/playbooks/{id}",
    params(
        ("id" = Uuid, Path, description = "Playbook ID")
    ),
    responses(
        (status = 200, description = "Playbook deleted successfully"),
        (status = 404, description = "Playbook not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "Playbooks"
)]
async fn delete_playbook(
    State(state): State<AppState>,
    RequireAdmin(_user): RequireAdmin,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    let repo: Box<dyn PlaybookRepository> = create_playbook_repository(&state.db);

    // Verify playbook exists and get name for toast
    let playbook: Playbook = repo
        .get(id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Playbook {} not found", id)))?;

    let deleted = repo.delete(id).await?;

    if !deleted {
        return Err(ApiError::Internal("Failed to delete playbook".to_string()));
    }

    let trigger = serde_json::json!({
        "showToast": {
            "type": "success",
            "title": "Playbook Deleted",
            "message": format!("Playbook '{}' has been deleted.", playbook.name)
        }
    });

    Ok((
        [(
            header::HeaderName::from_static("hx-trigger"),
            trigger.to_string(),
        )],
        "",
    ))
}

/// Toggle a playbook's enabled status.
#[utoipa::path(
    post,
    path = "/api/playbooks/{id}/toggle",
    params(
        ("id" = Uuid, Path, description = "Playbook ID")
    ),
    responses(
        (status = 200, description = "Playbook toggled successfully"),
        (status = 404, description = "Playbook not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "Playbooks"
)]
async fn toggle_playbook(
    State(state): State<AppState>,
    RequireAdmin(_user): RequireAdmin,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    let repo: Box<dyn PlaybookRepository> = create_playbook_repository(&state.db);

    // Toggle returns the updated playbook
    let playbook = repo.toggle_enabled(id).await?;

    let status_text = if playbook.enabled {
        "enabled"
    } else {
        "disabled"
    };

    let trigger = serde_json::json!({
        "showToast": {
            "type": "success",
            "title": "Playbook Updated",
            "message": format!("Playbook '{}' has been {}.", playbook.name, status_text)
        }
    });

    Ok((
        [(
            header::HeaderName::from_static("hx-trigger"),
            trigger.to_string(),
        )],
        "",
    ))
}

// ============================================================================
// Stage Management
// ============================================================================

/// Form data for adding/editing a stage.
#[derive(Debug, Deserialize)]
pub struct StageForm {
    pub name: String,
    pub description: Option<String>,
    #[serde(default)]
    pub parallel: Option<bool>,
}

/// Add a new stage to a playbook.
async fn add_stage(
    State(state): State<AppState>,
    RequireAdmin(_user): RequireAdmin,
    Path(id): Path<Uuid>,
    axum::Form(form): axum::Form<StageForm>,
) -> Result<impl IntoResponse, ApiError> {
    let repo = create_playbook_repository(&state.db);

    let mut playbook = repo
        .get(id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Playbook {} not found", id)))?;

    // Create the new stage
    let stage = PlaybookStage {
        name: form.name.clone(),
        description: form.description.filter(|d| !d.is_empty()),
        parallel: form.parallel.unwrap_or(false),
        steps: vec![],
    };

    playbook.stages.push(stage);

    // Update the playbook with new stages
    let update = PlaybookUpdate {
        stages: Some(playbook.stages),
        ..Default::default()
    };
    repo.update(id, &update).await?;

    let trigger = serde_json::json!({
        "showToast": {
            "type": "success",
            "title": "Stage Added",
            "message": format!("Stage '{}' has been added.", form.name)
        }
    });

    Ok((
        [(
            header::HeaderName::from_static("hx-trigger"),
            trigger.to_string(),
        )],
        "",
    ))
}

/// Update an existing stage.
async fn update_stage(
    State(state): State<AppState>,
    RequireAdmin(_user): RequireAdmin,
    Path((id, stage_index)): Path<(Uuid, usize)>,
    axum::Form(form): axum::Form<StageForm>,
) -> Result<impl IntoResponse, ApiError> {
    let repo = create_playbook_repository(&state.db);

    let mut playbook = repo
        .get(id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Playbook {} not found", id)))?;

    if stage_index >= playbook.stages.len() {
        return Err(ApiError::NotFound(format!(
            "Stage {} not found",
            stage_index
        )));
    }

    // Update the stage
    playbook.stages[stage_index].name = form.name.clone();
    playbook.stages[stage_index].description = form.description.filter(|d| !d.is_empty());
    playbook.stages[stage_index].parallel = form.parallel.unwrap_or(false);

    let update = PlaybookUpdate {
        stages: Some(playbook.stages),
        ..Default::default()
    };
    repo.update(id, &update).await?;

    let trigger = serde_json::json!({
        "showToast": {
            "type": "success",
            "title": "Stage Updated",
            "message": format!("Stage '{}' has been updated.", form.name)
        }
    });

    Ok((
        [(
            header::HeaderName::from_static("hx-trigger"),
            trigger.to_string(),
        )],
        "",
    ))
}

/// Delete a stage from a playbook.
async fn delete_stage(
    State(state): State<AppState>,
    RequireAdmin(_user): RequireAdmin,
    Path((id, stage_index)): Path<(Uuid, usize)>,
) -> Result<impl IntoResponse, ApiError> {
    let repo = create_playbook_repository(&state.db);

    let mut playbook = repo
        .get(id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Playbook {} not found", id)))?;

    if stage_index >= playbook.stages.len() {
        return Err(ApiError::NotFound(format!(
            "Stage {} not found",
            stage_index
        )));
    }

    let stage_name = playbook.stages[stage_index].name.clone();
    playbook.stages.remove(stage_index);

    let update = PlaybookUpdate {
        stages: Some(playbook.stages),
        ..Default::default()
    };
    repo.update(id, &update).await?;

    let trigger = serde_json::json!({
        "showToast": {
            "type": "success",
            "title": "Stage Deleted",
            "message": format!("Stage '{}' has been deleted.", stage_name)
        }
    });

    Ok((
        [(
            header::HeaderName::from_static("hx-trigger"),
            trigger.to_string(),
        )],
        "",
    ))
}

// ============================================================================
// Step Management
// ============================================================================

/// Form data for adding/editing a step.
#[derive(Debug, Deserialize)]
pub struct StepForm {
    pub action: String,
    pub parameters: Option<String>,
    pub input: Option<String>,
    pub output: Option<String>,
    pub conditions: Option<String>,
    #[serde(default)]
    pub requires_approval: Option<bool>,
}

/// Add a new step to a stage.
async fn add_step(
    State(state): State<AppState>,
    RequireAdmin(_user): RequireAdmin,
    Path((id, stage_index)): Path<(Uuid, usize)>,
    axum::Form(form): axum::Form<StepForm>,
) -> Result<impl IntoResponse, ApiError> {
    let repo = create_playbook_repository(&state.db);

    let mut playbook = repo
        .get(id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Playbook {} not found", id)))?;

    if stage_index >= playbook.stages.len() {
        return Err(ApiError::NotFound(format!(
            "Stage {} not found",
            stage_index
        )));
    }

    // Parse optional JSON fields
    let parameters = form
        .parameters
        .filter(|s| !s.is_empty())
        .map(|s| serde_json::from_str(&s))
        .transpose()
        .map_err(|e| ApiError::BadRequest(format!("Invalid parameters JSON: {}", e)))?;

    let input = form
        .input
        .filter(|s| !s.is_empty())
        .map(|s| serde_json::from_str(&s))
        .transpose()
        .map_err(|e| ApiError::BadRequest(format!("Invalid input JSON: {}", e)))?;

    let output = form
        .output
        .filter(|s| !s.is_empty())
        .map(|s| s.split(',').map(|v| v.trim().to_string()).collect());

    let conditions = form
        .conditions
        .filter(|s| !s.is_empty())
        .map(|s| serde_json::from_str(&s))
        .transpose()
        .map_err(|e| ApiError::BadRequest(format!("Invalid conditions JSON: {}", e)))?;

    let step = PlaybookStep {
        action: form.action.clone(),
        parameters,
        input,
        output,
        requires_approval: form.requires_approval.unwrap_or(false),
        conditions,
    };

    playbook.stages[stage_index].steps.push(step);

    let update = PlaybookUpdate {
        stages: Some(playbook.stages),
        ..Default::default()
    };
    repo.update(id, &update).await?;

    let trigger = serde_json::json!({
        "showToast": {
            "type": "success",
            "title": "Step Added",
            "message": format!("Step '{}' has been added.", form.action)
        }
    });

    Ok((
        [(
            header::HeaderName::from_static("hx-trigger"),
            trigger.to_string(),
        )],
        "",
    ))
}

/// Update an existing step.
async fn update_step(
    State(state): State<AppState>,
    RequireAdmin(_user): RequireAdmin,
    Path((id, stage_index, step_index)): Path<(Uuid, usize, usize)>,
    axum::Form(form): axum::Form<StepForm>,
) -> Result<impl IntoResponse, ApiError> {
    let repo = create_playbook_repository(&state.db);

    let mut playbook = repo
        .get(id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Playbook {} not found", id)))?;

    if stage_index >= playbook.stages.len() {
        return Err(ApiError::NotFound(format!(
            "Stage {} not found",
            stage_index
        )));
    }

    if step_index >= playbook.stages[stage_index].steps.len() {
        return Err(ApiError::NotFound(format!("Step {} not found", step_index)));
    }

    // Parse optional JSON fields
    let parameters = form
        .parameters
        .filter(|s| !s.is_empty())
        .map(|s| serde_json::from_str(&s))
        .transpose()
        .map_err(|e| ApiError::BadRequest(format!("Invalid parameters JSON: {}", e)))?;

    let input = form
        .input
        .filter(|s| !s.is_empty())
        .map(|s| serde_json::from_str(&s))
        .transpose()
        .map_err(|e| ApiError::BadRequest(format!("Invalid input JSON: {}", e)))?;

    let output = form
        .output
        .filter(|s| !s.is_empty())
        .map(|s| s.split(',').map(|v| v.trim().to_string()).collect());

    let conditions = form
        .conditions
        .filter(|s| !s.is_empty())
        .map(|s| serde_json::from_str(&s))
        .transpose()
        .map_err(|e| ApiError::BadRequest(format!("Invalid conditions JSON: {}", e)))?;

    playbook.stages[stage_index].steps[step_index] = PlaybookStep {
        action: form.action.clone(),
        parameters,
        input,
        output,
        requires_approval: form.requires_approval.unwrap_or(false),
        conditions,
    };

    let update = PlaybookUpdate {
        stages: Some(playbook.stages),
        ..Default::default()
    };
    repo.update(id, &update).await?;

    let trigger = serde_json::json!({
        "showToast": {
            "type": "success",
            "title": "Step Updated",
            "message": format!("Step '{}' has been updated.", form.action)
        }
    });

    Ok((
        [(
            header::HeaderName::from_static("hx-trigger"),
            trigger.to_string(),
        )],
        "",
    ))
}

/// Delete a step from a stage.
async fn delete_step(
    State(state): State<AppState>,
    RequireAdmin(_user): RequireAdmin,
    Path((id, stage_index, step_index)): Path<(Uuid, usize, usize)>,
) -> Result<impl IntoResponse, ApiError> {
    let repo = create_playbook_repository(&state.db);

    let mut playbook = repo
        .get(id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Playbook {} not found", id)))?;

    if stage_index >= playbook.stages.len() {
        return Err(ApiError::NotFound(format!(
            "Stage {} not found",
            stage_index
        )));
    }

    if step_index >= playbook.stages[stage_index].steps.len() {
        return Err(ApiError::NotFound(format!("Step {} not found", step_index)));
    }

    let step_action = playbook.stages[stage_index].steps[step_index]
        .action
        .clone();
    playbook.stages[stage_index].steps.remove(step_index);

    let update = PlaybookUpdate {
        stages: Some(playbook.stages),
        ..Default::default()
    };
    repo.update(id, &update).await?;

    let trigger = serde_json::json!({
        "showToast": {
            "type": "success",
            "title": "Step Deleted",
            "message": format!("Step '{}' has been deleted.", step_action)
        }
    });

    Ok((
        [(
            header::HeaderName::from_static("hx-trigger"),
            trigger.to_string(),
        )],
        "",
    ))
}

// ============================================================================
// Helper Functions
// ============================================================================

fn playbook_to_response(playbook: Playbook) -> PlaybookResponse {
    PlaybookResponse {
        id: playbook.id,
        name: playbook.name,
        description: playbook.description,
        trigger_type: playbook.trigger_type,
        trigger_condition: playbook.trigger_condition,
        stages: playbook.stages.into_iter().map(stage_to_dto).collect(),
        enabled: playbook.enabled,
        execution_count: playbook.execution_count,
        created_at: playbook.created_at,
        updated_at: playbook.updated_at,
    }
}

fn stage_to_dto(stage: PlaybookStage) -> PlaybookStageDto {
    PlaybookStageDto {
        name: stage.name,
        description: stage.description,
        parallel: stage.parallel,
        steps: stage.steps.into_iter().map(step_to_dto).collect(),
    }
}

fn step_to_dto(step: PlaybookStep) -> PlaybookStepDto {
    PlaybookStepDto {
        action: step.action,
        parameters: step.parameters,
        input: step.input,
        output: step.output,
        requires_approval: step.requires_approval,
        conditions: step.conditions,
    }
}

fn stage_dto_to_stage(dto: PlaybookStageDto) -> PlaybookStage {
    PlaybookStage {
        name: dto.name,
        description: dto.description,
        parallel: dto.parallel,
        steps: dto.steps.into_iter().map(step_dto_to_step).collect(),
    }
}

fn step_dto_to_step(dto: PlaybookStepDto) -> PlaybookStep {
    PlaybookStep {
        action: dto.action,
        parameters: dto.parameters,
        input: dto.input,
        output: dto.output,
        requires_approval: dto.requires_approval,
        conditions: dto.conditions,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{header, Request, StatusCode},
        Extension,
    };
    use tower::ServiceExt;
    use tw_core::{db::DbPool, EventBus};

    use crate::auth::test_helpers::TestUser;
    use crate::state::AppState;

    /// SQL to create the playbooks table for testing.
    const CREATE_PLAYBOOKS_TABLE: &str = r#"
        CREATE TABLE IF NOT EXISTS playbooks (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT,
            trigger_type TEXT NOT NULL,
            trigger_condition TEXT,
            stages TEXT NOT NULL DEFAULT '[]',
            enabled INTEGER NOT NULL DEFAULT 1,
            execution_count INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_playbooks_name ON playbooks(name);
        CREATE INDEX IF NOT EXISTS idx_playbooks_trigger_type ON playbooks(trigger_type);
        CREATE INDEX IF NOT EXISTS idx_playbooks_enabled ON playbooks(enabled);
    "#;

    /// Creates an in-memory SQLite database and returns the test app router.
    /// Returns both the router and the underlying SQLite pool for direct database access.
    async fn setup_test_app() -> (axum::Router, sqlx::SqlitePool) {
        // Use a unique UUID for complete database isolation
        let unique_id = uuid::Uuid::new_v4();
        let temp_dir = std::env::temp_dir();
        let db_path = temp_dir.join(format!("tw_api_playbook_test_{}.db", unique_id));
        let db_url = format!("sqlite:{}?mode=rwc", db_path.display());

        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect(&db_url)
            .await
            .expect("Failed to create SQLite pool");

        // Create tables directly
        sqlx::raw_sql(CREATE_PLAYBOOKS_TABLE)
            .execute(&pool)
            .await
            .expect("Failed to create tables");

        let db = DbPool::Sqlite(pool.clone());
        let event_bus = EventBus::new(100);
        let state = AppState::new(db, event_bus);

        // Create router with playbooks routes and admin authentication
        let router = axum::Router::new()
            .nest("/api/playbooks", routes())
            .layer(Extension(TestUser::admin()))
            .with_state(state);

        (router, pool)
    }

    /// Helper to create a playbook directly in the database for testing.
    async fn create_playbook_in_db(
        pool: &sqlx::SqlitePool,
        name: &str,
        trigger_type: &str,
    ) -> Uuid {
        use tw_core::db::create_playbook_repository;
        use tw_core::playbook::Playbook;

        let db = DbPool::Sqlite(pool.clone());
        let repo = create_playbook_repository(&db);
        let playbook = Playbook::new(name, trigger_type);
        let created = repo
            .create(&playbook)
            .await
            .expect("Failed to create test playbook");
        created.id
    }

    /// Helper to create a playbook with description.
    async fn create_playbook_with_description(
        pool: &sqlx::SqlitePool,
        name: &str,
        trigger_type: &str,
        description: &str,
    ) -> Uuid {
        use tw_core::db::create_playbook_repository;
        use tw_core::playbook::Playbook;

        let db = DbPool::Sqlite(pool.clone());
        let repo = create_playbook_repository(&db);
        let playbook = Playbook::new(name, trigger_type).with_description(description);
        let created = repo
            .create(&playbook)
            .await
            .expect("Failed to create test playbook");
        created.id
    }

    // ========================================================================
    // GET /api/playbooks - List Playbooks
    // ========================================================================

    #[tokio::test]
    async fn test_list_playbooks_empty() {
        let (app, _pool) = setup_test_app().await;

        let request = Request::builder()
            .method("GET")
            .uri("/api/playbooks")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let playbooks: Vec<PlaybookResponse> = serde_json::from_slice(&body).unwrap();

        assert!(playbooks.is_empty());
    }

    #[tokio::test]
    async fn test_list_playbooks_returns_json() {
        let (app, pool) = setup_test_app().await;

        // Create some playbooks
        create_playbook_in_db(&pool, "playbook-1", "alert").await;
        create_playbook_in_db(&pool, "playbook-2", "scheduled").await;
        create_playbook_in_db(&pool, "playbook-3", "webhook").await;

        let request = Request::builder()
            .method("GET")
            .uri("/api/playbooks")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Verify content type is JSON
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .expect("Content-Type header should be present");
        assert!(content_type.to_str().unwrap().contains("application/json"));

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let playbooks: Vec<PlaybookResponse> = serde_json::from_slice(&body).unwrap();

        assert_eq!(playbooks.len(), 3);
    }

    #[tokio::test]
    async fn test_list_playbooks_contains_expected_fields() {
        let (app, pool) = setup_test_app().await;

        create_playbook_with_description(&pool, "test-playbook", "alert", "Test description").await;

        let request = Request::builder()
            .method("GET")
            .uri("/api/playbooks")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let playbooks: Vec<PlaybookResponse> = serde_json::from_slice(&body).unwrap();

        assert_eq!(playbooks.len(), 1);
        let playbook = &playbooks[0];

        assert_eq!(playbook.name, "test-playbook");
        assert_eq!(playbook.trigger_type, "alert");
        assert_eq!(playbook.description, Some("Test description".to_string()));
        assert!(playbook.enabled);
        assert_eq!(playbook.execution_count, 0);
    }

    // ========================================================================
    // GET /api/playbooks/{id} - Get Single Playbook
    // ========================================================================

    #[tokio::test]
    async fn test_get_playbook_success() {
        let (app, pool) = setup_test_app().await;

        let playbook_id = create_playbook_with_description(
            &pool,
            "single-playbook",
            "alert",
            "A single playbook",
        )
        .await;

        let request = Request::builder()
            .method("GET")
            .uri(format!("/api/playbooks/{}", playbook_id))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let playbook: PlaybookResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(playbook.id, playbook_id);
        assert_eq!(playbook.name, "single-playbook");
        assert_eq!(playbook.trigger_type, "alert");
        assert_eq!(playbook.description, Some("A single playbook".to_string()));
    }

    #[tokio::test]
    async fn test_get_playbook_not_found() {
        let (app, _pool) = setup_test_app().await;

        let non_existent_id = Uuid::new_v4();

        let request = Request::builder()
            .method("GET")
            .uri(format!("/api/playbooks/{}", non_existent_id))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let error: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(error["code"], "NOT_FOUND");
    }

    // ========================================================================
    // POST /api/playbooks - Create Playbook
    // ========================================================================

    #[tokio::test]
    async fn test_create_playbook_success() {
        let (app, _pool) = setup_test_app().await;

        let form_data = serde_urlencoded::to_string([
            ("name", "new-playbook"),
            ("trigger_type", "alert"),
            ("description", "A new playbook"),
        ])
        .unwrap();

        let request = Request::builder()
            .method("POST")
            .uri("/api/playbooks")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(form_data))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Check HX-Trigger header for HTMX integration
        let hx_trigger = response
            .headers()
            .get("hx-trigger")
            .expect("HX-Trigger header should be present");

        let trigger_value: serde_json::Value =
            serde_json::from_str(hx_trigger.to_str().unwrap()).unwrap();
        assert_eq!(trigger_value["showToast"]["type"], "success");
        assert_eq!(trigger_value["showToast"]["title"], "Playbook Created");
    }

    #[tokio::test]
    async fn test_create_playbook_with_enabled_false() {
        let (app, pool) = setup_test_app().await;

        let form_data = serde_urlencoded::to_string([
            ("name", "disabled-playbook"),
            ("trigger_type", "scheduled"),
            ("enabled", "false"),
        ])
        .unwrap();

        let request = Request::builder()
            .method("POST")
            .uri("/api/playbooks")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(form_data))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Verify the playbook was created with enabled=false
        use tw_core::db::create_playbook_repository;
        let db = DbPool::Sqlite(pool.clone());
        let repo = create_playbook_repository(&db);
        let playbook = repo
            .get_by_name("disabled-playbook")
            .await
            .unwrap()
            .expect("Playbook should exist");

        assert!(!playbook.enabled);
    }

    #[tokio::test]
    async fn test_create_playbook_duplicate_name_conflict() {
        let (app, pool) = setup_test_app().await;

        // Create a playbook first
        create_playbook_in_db(&pool, "duplicate-name", "alert").await;

        // Try to create another with the same name
        let form_data =
            serde_urlencoded::to_string([("name", "duplicate-name"), ("trigger_type", "webhook")])
                .unwrap();

        let request = Request::builder()
            .method("POST")
            .uri("/api/playbooks")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(form_data))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::CONFLICT);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let error: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(error["code"], "CONFLICT");
        assert!(error["message"]
            .as_str()
            .unwrap()
            .contains("duplicate-name"));
    }

    #[tokio::test]
    async fn test_create_playbook_with_stages() {
        let (app, pool) = setup_test_app().await;

        let stages_json = r#"[{"name":"extraction","description":"Extract indicators","parallel":true,"steps":[{"action":"parse_email"}]}]"#;

        let form_data = serde_urlencoded::to_string([
            ("name", "playbook-with-stages"),
            ("trigger_type", "alert"),
            ("stages", stages_json),
        ])
        .unwrap();

        let request = Request::builder()
            .method("POST")
            .uri("/api/playbooks")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(form_data))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Verify stages were saved
        use tw_core::db::create_playbook_repository;
        let db = DbPool::Sqlite(pool.clone());
        let repo = create_playbook_repository(&db);
        let playbook = repo
            .get_by_name("playbook-with-stages")
            .await
            .unwrap()
            .expect("Playbook should exist");

        assert_eq!(playbook.stages.len(), 1);
        assert_eq!(playbook.stages[0].name, "extraction");
        assert!(playbook.stages[0].parallel);
    }

    // ========================================================================
    // PUT /api/playbooks/{id} - Update Playbook
    // ========================================================================

    #[tokio::test]
    async fn test_update_playbook_success() {
        let (app, pool) = setup_test_app().await;

        let playbook_id = create_playbook_in_db(&pool, "original-name", "alert").await;

        let form_data = serde_urlencoded::to_string([
            ("name", "updated-name"),
            ("description", "Updated description"),
        ])
        .unwrap();

        let request = Request::builder()
            .method("PUT")
            .uri(format!("/api/playbooks/{}", playbook_id))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(form_data))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Check HX-Trigger header
        let hx_trigger = response
            .headers()
            .get("hx-trigger")
            .expect("HX-Trigger header should be present");

        let trigger_value: serde_json::Value =
            serde_json::from_str(hx_trigger.to_str().unwrap()).unwrap();
        assert_eq!(trigger_value["showToast"]["type"], "success");
        assert_eq!(trigger_value["showToast"]["title"], "Playbook Updated");

        // Verify the update was applied
        use tw_core::db::create_playbook_repository;
        let db = DbPool::Sqlite(pool.clone());
        let repo = create_playbook_repository(&db);
        let playbook = repo
            .get(playbook_id)
            .await
            .unwrap()
            .expect("Playbook should exist");

        assert_eq!(playbook.name, "updated-name");
        assert_eq!(
            playbook.description,
            Some("Updated description".to_string())
        );
    }

    #[tokio::test]
    async fn test_update_playbook_not_found() {
        let (app, _pool) = setup_test_app().await;

        let non_existent_id = Uuid::new_v4();

        let form_data = serde_urlencoded::to_string([("name", "updated-name")]).unwrap();

        let request = Request::builder()
            .method("PUT")
            .uri(format!("/api/playbooks/{}", non_existent_id))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(form_data))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let error: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(error["code"], "NOT_FOUND");
    }

    #[tokio::test]
    async fn test_update_playbook_name_conflict() {
        let (app, pool) = setup_test_app().await;

        // Create two playbooks
        let playbook_id = create_playbook_in_db(&pool, "playbook-a", "alert").await;
        create_playbook_in_db(&pool, "playbook-b", "alert").await;

        // Try to rename playbook-a to playbook-b
        let form_data = serde_urlencoded::to_string([("name", "playbook-b")]).unwrap();

        let request = Request::builder()
            .method("PUT")
            .uri(format!("/api/playbooks/{}", playbook_id))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(form_data))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::CONFLICT);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let error: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(error["code"], "CONFLICT");
    }

    #[tokio::test]
    async fn test_update_playbook_toggle_enabled() {
        let (app, pool) = setup_test_app().await;

        let playbook_id = create_playbook_in_db(&pool, "toggle-test", "alert").await;

        let form_data = serde_urlencoded::to_string([("enabled", "false")]).unwrap();

        let request = Request::builder()
            .method("PUT")
            .uri(format!("/api/playbooks/{}", playbook_id))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(form_data))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Verify the update was applied
        use tw_core::db::create_playbook_repository;
        let db = DbPool::Sqlite(pool.clone());
        let repo = create_playbook_repository(&db);
        let playbook = repo
            .get(playbook_id)
            .await
            .unwrap()
            .expect("Playbook should exist");

        assert!(!playbook.enabled);
    }

    // ========================================================================
    // DELETE /api/playbooks/{id} - Delete Playbook
    // ========================================================================

    #[tokio::test]
    async fn test_delete_playbook_success() {
        let (app, pool) = setup_test_app().await;

        let playbook_id = create_playbook_in_db(&pool, "to-delete", "alert").await;

        let request = Request::builder()
            .method("DELETE")
            .uri(format!("/api/playbooks/{}", playbook_id))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Check HX-Trigger header
        let hx_trigger = response
            .headers()
            .get("hx-trigger")
            .expect("HX-Trigger header should be present");

        let trigger_value: serde_json::Value =
            serde_json::from_str(hx_trigger.to_str().unwrap()).unwrap();
        assert_eq!(trigger_value["showToast"]["type"], "success");
        assert_eq!(trigger_value["showToast"]["title"], "Playbook Deleted");

        // Verify the playbook was deleted
        use tw_core::db::create_playbook_repository;
        let db = DbPool::Sqlite(pool.clone());
        let repo = create_playbook_repository(&db);
        let playbook = repo.get(playbook_id).await.unwrap();

        assert!(playbook.is_none());
    }

    #[tokio::test]
    async fn test_delete_playbook_not_found() {
        let (app, _pool) = setup_test_app().await;

        let non_existent_id = Uuid::new_v4();

        let request = Request::builder()
            .method("DELETE")
            .uri(format!("/api/playbooks/{}", non_existent_id))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let error: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(error["code"], "NOT_FOUND");
    }

    // ========================================================================
    // POST /api/playbooks/{id}/toggle - Toggle Playbook Enabled Status
    // ========================================================================

    #[tokio::test]
    async fn test_toggle_playbook_enabled_to_disabled() {
        let (app, pool) = setup_test_app().await;

        // Create an enabled playbook (default)
        let playbook_id = create_playbook_in_db(&pool, "toggle-playbook", "alert").await;

        // Verify it starts enabled
        {
            use tw_core::db::create_playbook_repository;
            let db = DbPool::Sqlite(pool.clone());
            let repo = create_playbook_repository(&db);
            let playbook = repo
                .get(playbook_id)
                .await
                .unwrap()
                .expect("Playbook should exist");
            assert!(playbook.enabled);
        }

        let request = Request::builder()
            .method("POST")
            .uri(format!("/api/playbooks/{}/toggle", playbook_id))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Check HX-Trigger header
        let hx_trigger = response
            .headers()
            .get("hx-trigger")
            .expect("HX-Trigger header should be present");

        let trigger_value: serde_json::Value =
            serde_json::from_str(hx_trigger.to_str().unwrap()).unwrap();
        assert_eq!(trigger_value["showToast"]["type"], "success");
        assert!(trigger_value["showToast"]["message"]
            .as_str()
            .unwrap()
            .contains("disabled"));

        // Verify it's now disabled
        use tw_core::db::create_playbook_repository;
        let db = DbPool::Sqlite(pool.clone());
        let repo = create_playbook_repository(&db);
        let playbook = repo
            .get(playbook_id)
            .await
            .unwrap()
            .expect("Playbook should exist");

        assert!(!playbook.enabled);
    }

    #[tokio::test]
    async fn test_toggle_playbook_disabled_to_enabled() {
        let (app, pool) = setup_test_app().await;

        // Create a disabled playbook
        use tw_core::db::create_playbook_repository;
        use tw_core::playbook::Playbook;

        let db = DbPool::Sqlite(pool.clone());
        let repo = create_playbook_repository(&db);
        let playbook = Playbook::new("disabled-toggle", "alert").with_enabled(false);
        let created = repo
            .create(&playbook)
            .await
            .expect("Failed to create playbook");
        let playbook_id = created.id;

        // Verify it starts disabled
        assert!(!created.enabled);

        let request = Request::builder()
            .method("POST")
            .uri(format!("/api/playbooks/{}/toggle", playbook_id))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Check the toast message indicates it's now enabled
        let hx_trigger = response
            .headers()
            .get("hx-trigger")
            .expect("HX-Trigger header should be present");

        let trigger_value: serde_json::Value =
            serde_json::from_str(hx_trigger.to_str().unwrap()).unwrap();
        assert!(trigger_value["showToast"]["message"]
            .as_str()
            .unwrap()
            .contains("enabled"));

        // Verify it's now enabled
        let db = DbPool::Sqlite(pool.clone());
        let repo = create_playbook_repository(&db);
        let playbook = repo
            .get(playbook_id)
            .await
            .unwrap()
            .expect("Playbook should exist");

        assert!(playbook.enabled);
    }

    #[tokio::test]
    async fn test_toggle_playbook_not_found() {
        let (app, _pool) = setup_test_app().await;

        let non_existent_id = Uuid::new_v4();

        let request = Request::builder()
            .method("POST")
            .uri(format!("/api/playbooks/{}/toggle", non_existent_id))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let error: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(error["code"], "NOT_FOUND");
    }

    #[tokio::test]
    async fn test_toggle_playbook_multiple_times() {
        let (app, pool) = setup_test_app().await;

        let playbook_id = create_playbook_in_db(&pool, "multi-toggle", "alert").await;

        // Toggle 1: enabled -> disabled
        let request = Request::builder()
            .method("POST")
            .uri(format!("/api/playbooks/{}/toggle", playbook_id))
            .body(Body::empty())
            .unwrap();

        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        {
            use tw_core::db::create_playbook_repository;
            let db = DbPool::Sqlite(pool.clone());
            let repo = create_playbook_repository(&db);
            let playbook = repo
                .get(playbook_id)
                .await
                .unwrap()
                .expect("Playbook should exist");
            assert!(!playbook.enabled);
        }

        // Toggle 2: disabled -> enabled
        let request = Request::builder()
            .method("POST")
            .uri(format!("/api/playbooks/{}/toggle", playbook_id))
            .body(Body::empty())
            .unwrap();

        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        {
            use tw_core::db::create_playbook_repository;
            let db = DbPool::Sqlite(pool.clone());
            let repo = create_playbook_repository(&db);
            let playbook = repo
                .get(playbook_id)
                .await
                .unwrap()
                .expect("Playbook should exist");
            assert!(playbook.enabled);
        }

        // Toggle 3: enabled -> disabled
        let request = Request::builder()
            .method("POST")
            .uri(format!("/api/playbooks/{}/toggle", playbook_id))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        use tw_core::db::create_playbook_repository;
        let db = DbPool::Sqlite(pool.clone());
        let repo = create_playbook_repository(&db);
        let playbook = repo
            .get(playbook_id)
            .await
            .unwrap()
            .expect("Playbook should exist");
        assert!(!playbook.enabled);
    }

    // ========================================================================
    // Additional Edge Case Tests
    // ========================================================================

    #[tokio::test]
    async fn test_create_playbook_invalid_stages_json() {
        let (app, _pool) = setup_test_app().await;

        // Malformed JSON in stages
        let form_data = serde_urlencoded::to_string([
            ("name", "bad-stages-playbook"),
            ("trigger_type", "alert"),
            ("stages", "this is not valid json"),
        ])
        .unwrap();

        let request = Request::builder()
            .method("POST")
            .uri("/api/playbooks")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(form_data))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let error: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(error["code"], "BAD_REQUEST");
        assert!(error["message"]
            .as_str()
            .unwrap()
            .contains("Invalid stages JSON"));
    }

    #[tokio::test]
    async fn test_update_playbook_invalid_stages_json() {
        let (app, pool) = setup_test_app().await;

        let playbook_id = create_playbook_in_db(&pool, "update-bad-stages", "alert").await;

        // Malformed JSON in stages
        let form_data = serde_urlencoded::to_string([("stages", "[{invalid json}]")]).unwrap();

        let request = Request::builder()
            .method("PUT")
            .uri(format!("/api/playbooks/{}", playbook_id))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(form_data))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let error: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(error["code"], "BAD_REQUEST");
        assert!(error["message"]
            .as_str()
            .unwrap()
            .contains("Invalid stages JSON"));
    }

    #[tokio::test]
    async fn test_update_playbook_same_name_no_conflict() {
        let (app, pool) = setup_test_app().await;

        let playbook_id = create_playbook_in_db(&pool, "keep-same-name", "alert").await;

        // Update with the same name should not cause a conflict
        let form_data = serde_urlencoded::to_string([
            ("name", "keep-same-name"),
            ("description", "Updated description"),
        ])
        .unwrap();

        let request = Request::builder()
            .method("PUT")
            .uri(format!("/api/playbooks/{}", playbook_id))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(form_data))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Verify the description was updated
        use tw_core::db::create_playbook_repository;
        let db = DbPool::Sqlite(pool.clone());
        let repo = create_playbook_repository(&db);
        let playbook = repo
            .get(playbook_id)
            .await
            .unwrap()
            .expect("Playbook should exist");

        assert_eq!(playbook.name, "keep-same-name");
        assert_eq!(
            playbook.description,
            Some("Updated description".to_string())
        );
    }

    #[tokio::test]
    async fn test_update_playbook_clear_description() {
        let (app, pool) = setup_test_app().await;

        let playbook_id = create_playbook_with_description(
            &pool,
            "clear-description",
            "alert",
            "Original description",
        )
        .await;

        // Update with empty description to clear it
        let form_data = serde_urlencoded::to_string([("description", "")]).unwrap();

        let request = Request::builder()
            .method("PUT")
            .uri(format!("/api/playbooks/{}", playbook_id))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(form_data))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Verify the description was cleared
        use tw_core::db::create_playbook_repository;
        let db = DbPool::Sqlite(pool.clone());
        let repo = create_playbook_repository(&db);
        let playbook = repo
            .get(playbook_id)
            .await
            .unwrap()
            .expect("Playbook should exist");

        assert!(playbook.description.is_none());
    }

    #[tokio::test]
    async fn test_update_playbook_clear_trigger_condition() {
        let (app, pool) = setup_test_app().await;

        // Create a playbook with trigger condition
        use tw_core::db::create_playbook_repository;
        use tw_core::playbook::Playbook;

        let db = DbPool::Sqlite(pool.clone());
        let repo = create_playbook_repository(&db);
        let playbook =
            Playbook::new("clear-condition", "alert").with_trigger_condition("severity == 'high'");
        let created = repo
            .create(&playbook)
            .await
            .expect("Failed to create playbook");
        let playbook_id = created.id;

        // Verify initial condition
        assert!(created.trigger_condition.is_some());

        // Update with empty trigger_condition to clear it
        let form_data = serde_urlencoded::to_string([("trigger_condition", "")]).unwrap();

        let request = Request::builder()
            .method("PUT")
            .uri(format!("/api/playbooks/{}", playbook_id))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(form_data))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Verify the trigger_condition was cleared
        let db = DbPool::Sqlite(pool.clone());
        let repo = create_playbook_repository(&db);
        let playbook = repo
            .get(playbook_id)
            .await
            .unwrap()
            .expect("Playbook should exist");

        assert!(playbook.trigger_condition.is_none());
    }

    #[tokio::test]
    async fn test_update_playbook_change_trigger_type() {
        let (app, pool) = setup_test_app().await;

        let playbook_id = create_playbook_in_db(&pool, "change-trigger", "alert").await;

        // Update trigger type
        let form_data = serde_urlencoded::to_string([("trigger_type", "scheduled")]).unwrap();

        let request = Request::builder()
            .method("PUT")
            .uri(format!("/api/playbooks/{}", playbook_id))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(form_data))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Verify the trigger_type was updated
        use tw_core::db::create_playbook_repository;
        let db = DbPool::Sqlite(pool.clone());
        let repo = create_playbook_repository(&db);
        let playbook = repo
            .get(playbook_id)
            .await
            .unwrap()
            .expect("Playbook should exist");

        assert_eq!(playbook.trigger_type, "scheduled");
    }

    #[tokio::test]
    async fn test_update_playbook_stages() {
        let (app, pool) = setup_test_app().await;

        let playbook_id = create_playbook_in_db(&pool, "update-stages", "alert").await;

        // Update with new stages
        let stages_json = r#"[{"name":"new-stage","description":"New stage description","parallel":false,"steps":[{"action":"notify"}]}]"#;
        let form_data = serde_urlencoded::to_string([("stages", stages_json)]).unwrap();

        let request = Request::builder()
            .method("PUT")
            .uri(format!("/api/playbooks/{}", playbook_id))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(form_data))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Verify the stages were updated
        use tw_core::db::create_playbook_repository;
        let db = DbPool::Sqlite(pool.clone());
        let repo = create_playbook_repository(&db);
        let playbook = repo
            .get(playbook_id)
            .await
            .unwrap()
            .expect("Playbook should exist");

        assert_eq!(playbook.stages.len(), 1);
        assert_eq!(playbook.stages[0].name, "new-stage");
        assert_eq!(
            playbook.stages[0].description,
            Some("New stage description".to_string())
        );
        assert!(!playbook.stages[0].parallel);
        assert_eq!(playbook.stages[0].steps.len(), 1);
        assert_eq!(playbook.stages[0].steps[0].action, "notify");
    }

    #[tokio::test]
    async fn test_create_playbook_with_trigger_condition() {
        let (app, pool) = setup_test_app().await;

        let form_data = serde_urlencoded::to_string([
            ("name", "conditional-playbook"),
            ("trigger_type", "alert"),
            ("trigger_condition", "severity == 'critical'"),
        ])
        .unwrap();

        let request = Request::builder()
            .method("POST")
            .uri("/api/playbooks")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(form_data))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Verify the playbook was created with the trigger condition
        use tw_core::db::create_playbook_repository;
        let db = DbPool::Sqlite(pool.clone());
        let repo = create_playbook_repository(&db);
        let playbook = repo
            .get_by_name("conditional-playbook")
            .await
            .unwrap()
            .expect("Playbook should exist");

        assert_eq!(
            playbook.trigger_condition,
            Some("severity == 'critical'".to_string())
        );
    }

    #[tokio::test]
    async fn test_get_playbook_with_stages() {
        let (app, pool) = setup_test_app().await;

        // Create a playbook with stages via the repository directly
        use tw_core::db::create_playbook_repository;
        use tw_core::playbook::{Playbook, PlaybookStage, PlaybookStep};

        let db = DbPool::Sqlite(pool.clone());
        let repo = create_playbook_repository(&db);

        let stage = PlaybookStage {
            name: "enrichment".to_string(),
            description: Some("Enrich the alert data".to_string()),
            parallel: true,
            steps: vec![
                PlaybookStep {
                    action: "lookup_ip".to_string(),
                    parameters: Some(serde_json::json!({"service": "virustotal"})),
                    input: None,
                    output: Some(vec!["ip_reputation".to_string()]),
                    requires_approval: false,
                    conditions: None,
                },
                PlaybookStep {
                    action: "lookup_domain".to_string(),
                    parameters: None,
                    input: None,
                    output: None,
                    requires_approval: true,
                    conditions: Some(serde_json::json!({"if": "domain_present"})),
                },
            ],
        };

        let playbook = Playbook::new("playbook-with-stages", "alert").with_stages(vec![stage]);
        let created = repo
            .create(&playbook)
            .await
            .expect("Failed to create playbook");

        // Now fetch via the API
        let request = Request::builder()
            .method("GET")
            .uri(format!("/api/playbooks/{}", created.id))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let playbook_resp: PlaybookResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(playbook_resp.stages.len(), 1);
        let stage = &playbook_resp.stages[0];
        assert_eq!(stage.name, "enrichment");
        assert_eq!(stage.description, Some("Enrich the alert data".to_string()));
        assert!(stage.parallel);
        assert_eq!(stage.steps.len(), 2);

        // Check first step
        assert_eq!(stage.steps[0].action, "lookup_ip");
        assert!(stage.steps[0].parameters.is_some());
        assert_eq!(
            stage.steps[0].output,
            Some(vec!["ip_reputation".to_string()])
        );
        assert!(!stage.steps[0].requires_approval);

        // Check second step
        assert_eq!(stage.steps[1].action, "lookup_domain");
        assert!(stage.steps[1].requires_approval);
        assert!(stage.steps[1].conditions.is_some());
    }

    #[tokio::test]
    async fn test_get_playbook_invalid_uuid() {
        let (app, _pool) = setup_test_app().await;

        let request = Request::builder()
            .method("GET")
            .uri("/api/playbooks/not-a-valid-uuid")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        // Axum returns 400 Bad Request for invalid path parameters
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_delete_playbook_invalid_uuid() {
        let (app, _pool) = setup_test_app().await;

        let request = Request::builder()
            .method("DELETE")
            .uri("/api/playbooks/invalid-uuid")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_toggle_playbook_invalid_uuid() {
        let (app, _pool) = setup_test_app().await;

        let request = Request::builder()
            .method("POST")
            .uri("/api/playbooks/xyz-not-uuid/toggle")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_create_playbook_empty_stages_string_ignored() {
        let (app, pool) = setup_test_app().await;

        // Empty stages string should be ignored (not cause an error)
        let form_data = serde_urlencoded::to_string([
            ("name", "empty-stages-playbook"),
            ("trigger_type", "alert"),
            ("stages", ""),
        ])
        .unwrap();

        let request = Request::builder()
            .method("POST")
            .uri("/api/playbooks")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(form_data))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Verify the playbook was created with empty stages
        use tw_core::db::create_playbook_repository;
        let db = DbPool::Sqlite(pool.clone());
        let repo = create_playbook_repository(&db);
        let playbook = repo
            .get_by_name("empty-stages-playbook")
            .await
            .unwrap()
            .expect("Playbook should exist");

        assert!(playbook.stages.is_empty());
    }

    #[tokio::test]
    async fn test_create_playbook_empty_description_not_set() {
        let (app, pool) = setup_test_app().await;

        // Empty description should not be set
        let form_data = serde_urlencoded::to_string([
            ("name", "no-description-playbook"),
            ("trigger_type", "alert"),
            ("description", ""),
        ])
        .unwrap();

        let request = Request::builder()
            .method("POST")
            .uri("/api/playbooks")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(form_data))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Verify the playbook was created without description
        use tw_core::db::create_playbook_repository;
        let db = DbPool::Sqlite(pool.clone());
        let repo = create_playbook_repository(&db);
        let playbook = repo
            .get_by_name("no-description-playbook")
            .await
            .unwrap()
            .expect("Playbook should exist");

        assert!(playbook.description.is_none());
    }

    #[tokio::test]
    async fn test_create_playbook_empty_trigger_condition_not_set() {
        let (app, pool) = setup_test_app().await;

        // Empty trigger_condition should not be set
        let form_data = serde_urlencoded::to_string([
            ("name", "no-condition-playbook"),
            ("trigger_type", "alert"),
            ("trigger_condition", ""),
        ])
        .unwrap();

        let request = Request::builder()
            .method("POST")
            .uri("/api/playbooks")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(form_data))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Verify the playbook was created without trigger_condition
        use tw_core::db::create_playbook_repository;
        let db = DbPool::Sqlite(pool.clone());
        let repo = create_playbook_repository(&db);
        let playbook = repo
            .get_by_name("no-condition-playbook")
            .await
            .unwrap()
            .expect("Playbook should exist");

        assert!(playbook.trigger_condition.is_none());
    }
}
