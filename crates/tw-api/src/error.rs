//! API error types and handling.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use utoipa::ToSchema;

/// API error type.
#[derive(Error, Debug)]
pub enum ApiError {
    /// Resource not found.
    #[error("Not found: {0}")]
    NotFound(String),

    /// Bad request (validation error, invalid input).
    #[error("Bad request: {0}")]
    BadRequest(String),

    /// Unauthorized (missing or invalid authentication).
    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    /// Forbidden (authenticated but not allowed).
    #[error("Forbidden: {0}")]
    Forbidden(String),

    /// Conflict (e.g., duplicate resource).
    #[error("Conflict: {0}")]
    Conflict(String),

    /// Unprocessable entity (semantic errors).
    #[error("Unprocessable entity: {0}")]
    UnprocessableEntity(String),

    /// Rate limit exceeded.
    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    /// Internal server error.
    #[error("Internal error: {0}")]
    Internal(String),

    /// Database error.
    #[error("Database error: {0}")]
    Database(String),

    /// Webhook signature validation failed.
    #[error("Invalid webhook signature")]
    InvalidSignature,

    /// Service unavailable (e.g., during shutdown).
    #[error("Service unavailable: {0}")]
    ServiceUnavailable(String),

    /// Invalid login credentials.
    #[error("Invalid username or password")]
    InvalidCredentials,

    /// Session expired or invalid.
    #[error("Session expired")]
    SessionExpired,

    /// CSRF token validation failed.
    #[error("CSRF validation failed")]
    CsrfValidationFailed,

    /// Account is disabled.
    #[error("Account disabled")]
    AccountDisabled,
}

/// JSON error response body.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ErrorResponse {
    /// Error code for programmatic handling.
    pub code: String,
    /// Human-readable error message.
    pub message: String,
    /// Additional error details (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
    /// Request ID for tracing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

impl ApiError {
    /// Returns the HTTP status code for this error.
    pub fn status_code(&self) -> StatusCode {
        match self {
            ApiError::NotFound(_) => StatusCode::NOT_FOUND,
            ApiError::BadRequest(_) => StatusCode::BAD_REQUEST,
            ApiError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            ApiError::Forbidden(_) => StatusCode::FORBIDDEN,
            ApiError::Conflict(_) => StatusCode::CONFLICT,
            ApiError::UnprocessableEntity(_) => StatusCode::UNPROCESSABLE_ENTITY,
            ApiError::RateLimitExceeded => StatusCode::TOO_MANY_REQUESTS,
            ApiError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            ApiError::Database(_) => StatusCode::INTERNAL_SERVER_ERROR,
            ApiError::InvalidSignature => StatusCode::UNAUTHORIZED,
            ApiError::ServiceUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            ApiError::InvalidCredentials => StatusCode::UNAUTHORIZED,
            ApiError::SessionExpired => StatusCode::UNAUTHORIZED,
            ApiError::CsrfValidationFailed => StatusCode::FORBIDDEN,
            ApiError::AccountDisabled => StatusCode::FORBIDDEN,
        }
    }

    /// Returns the error code for this error.
    pub fn error_code(&self) -> &'static str {
        match self {
            ApiError::NotFound(_) => "NOT_FOUND",
            ApiError::BadRequest(_) => "BAD_REQUEST",
            ApiError::Unauthorized(_) => "UNAUTHORIZED",
            ApiError::Forbidden(_) => "FORBIDDEN",
            ApiError::Conflict(_) => "CONFLICT",
            ApiError::UnprocessableEntity(_) => "UNPROCESSABLE_ENTITY",
            ApiError::RateLimitExceeded => "RATE_LIMIT_EXCEEDED",
            ApiError::Internal(_) => "INTERNAL_ERROR",
            ApiError::Database(_) => "DATABASE_ERROR",
            ApiError::InvalidSignature => "INVALID_SIGNATURE",
            ApiError::ServiceUnavailable(_) => "SERVICE_UNAVAILABLE",
            ApiError::InvalidCredentials => "INVALID_CREDENTIALS",
            ApiError::SessionExpired => "SESSION_EXPIRED",
            ApiError::CsrfValidationFailed => "CSRF_VALIDATION_FAILED",
            ApiError::AccountDisabled => "ACCOUNT_DISABLED",
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let body = ErrorResponse {
            code: self.error_code().to_string(),
            message: self.to_string(),
            details: None,
            request_id: None,
        };

        (status, Json(body)).into_response()
    }
}

impl From<tw_core::db::DbError> for ApiError {
    fn from(err: tw_core::db::DbError) -> Self {
        match err {
            tw_core::db::DbError::NotFound { entity, id } => {
                ApiError::NotFound(format!("{} with id {} not found", entity, id))
            }
            tw_core::db::DbError::Constraint(msg) => ApiError::Conflict(msg),
            tw_core::db::DbError::Serialization(msg) => ApiError::BadRequest(msg),
            err => ApiError::Database(err.to_string()),
        }
    }
}

impl From<serde_json::Error> for ApiError {
    fn from(err: serde_json::Error) -> Self {
        ApiError::BadRequest(format!("JSON error: {}", err))
    }
}

impl From<validator::ValidationErrors> for ApiError {
    fn from(err: validator::ValidationErrors) -> Self {
        ApiError::UnprocessableEntity(format!("Validation failed: {}", err))
    }
}
