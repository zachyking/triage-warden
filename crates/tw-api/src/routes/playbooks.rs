//! Playbook management endpoints.

use axum::{
    extract::{Path, State},
    http::header,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use uuid::Uuid;

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
            "/{id}",
            get(get_playbook)
                .put(update_playbook)
                .delete(delete_playbook),
        )
        .route("/{id}/toggle", post(toggle_playbook))
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
