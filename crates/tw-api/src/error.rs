//! API error types and handling.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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

    /// Validation error with field-level details.
    #[error("Validation failed")]
    ValidationError(ValidationErrorDetails),

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

/// Details for field-level validation errors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationErrorDetails {
    /// Overall validation error message.
    pub message: String,
    /// Field-specific errors.
    pub fields: HashMap<String, Vec<FieldError>>,
}

/// A single field validation error.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldError {
    /// Error code (e.g., "required", "min_length", "invalid_format").
    pub code: String,
    /// Human-readable error message.
    pub message: String,
    /// Additional error parameters (e.g., min_length value).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Value>,
}

impl ValidationErrorDetails {
    /// Creates a new validation error with a single field error.
    pub fn field(field: &str, code: &str, message: &str) -> Self {
        let mut fields = HashMap::new();
        fields.insert(
            field.to_string(),
            vec![FieldError {
                code: code.to_string(),
                message: message.to_string(),
                params: None,
            }],
        );
        Self {
            message: format!("Validation failed for field '{}'", field),
            fields,
        }
    }

    /// Creates a validation error from multiple field errors.
    pub fn from_fields(errors: HashMap<String, Vec<FieldError>>) -> Self {
        let field_count = errors.len();
        let message = if field_count == 1 {
            let field = errors.keys().next().unwrap();
            format!("Validation failed for field '{}'", field)
        } else {
            format!("Validation failed for {} fields", field_count)
        };
        Self {
            message,
            fields: errors,
        }
    }

    /// Adds a field error.
    pub fn add_error(&mut self, field: &str, code: &str, message: &str) {
        self.fields
            .entry(field.to_string())
            .or_default()
            .push(FieldError {
                code: code.to_string(),
                message: message.to_string(),
                params: None,
            });
    }
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
            ApiError::ValidationError(_) => StatusCode::UNPROCESSABLE_ENTITY,
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
            ApiError::ValidationError(_) => "VALIDATION_ERROR",
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

    /// Creates a validation error for a single field.
    pub fn validation_field(field: &str, code: &str, message: &str) -> Self {
        ApiError::ValidationError(ValidationErrorDetails::field(field, code, message))
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let (message, details) = match &self {
            ApiError::ValidationError(details) => (
                details.message.clone(),
                Some(serde_json::to_value(&details.fields).unwrap_or_default()),
            ),
            _ => (self.to_string(), None),
        };

        let body = ErrorResponse {
            code: self.error_code().to_string(),
            message,
            details,
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
        let mut fields: HashMap<String, Vec<FieldError>> = HashMap::new();

        for (field_name, field_errors) in err.field_errors() {
            let errors: Vec<FieldError> = field_errors
                .iter()
                .map(|e| {
                    let code = e.code.to_string();
                    let message = e.message.clone().map(|m| m.to_string()).unwrap_or_else(|| {
                        format!("Field '{}' failed validation: {}", field_name, code)
                    });
                    let params = if e.params.is_empty() {
                        None
                    } else {
                        Some(serde_json::to_value(&e.params).unwrap_or_default())
                    };
                    FieldError {
                        code,
                        message,
                        params,
                    }
                })
                .collect();
            fields.insert(field_name.to_string(), errors);
        }

        ApiError::ValidationError(ValidationErrorDetails::from_fields(fields))
    }
}
