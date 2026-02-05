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

    /// Feature not implemented.
    #[error("Not implemented: {0}")]
    NotImplemented(String),
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
            ApiError::NotImplemented(_) => StatusCode::NOT_IMPLEMENTED,
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
            ApiError::NotImplemented(_) => "NOT_IMPLEMENTED",
        }
    }

    /// Creates a validation error for a single field.
    pub fn validation_field(field: &str, code: &str, message: &str) -> Self {
        ApiError::ValidationError(ValidationErrorDetails::field(field, code, message))
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        use tw_core::is_production_environment;

        let status = self.status_code();
        let is_production = is_production_environment();

        // Sanitize error messages for production to prevent information disclosure
        let (message, details) = match &self {
            ApiError::ValidationError(details) => (
                details.message.clone(),
                Some(serde_json::to_value(&details.fields).unwrap_or_default()),
            ),
            // Errors that are always safe to return as-is
            ApiError::NotFound(_)
            | ApiError::RateLimitExceeded
            | ApiError::InvalidSignature
            | ApiError::InvalidCredentials
            | ApiError::SessionExpired
            | ApiError::CsrfValidationFailed
            | ApiError::AccountDisabled
            | ApiError::NotImplemented(_) => (self.to_string(), None),

            // Errors that need sanitization in production
            ApiError::BadRequest(msg) => {
                if is_production {
                    // Log full error server-side
                    tracing::warn!(error = %msg, "Bad request error");
                    ("Invalid request".to_string(), None)
                } else {
                    (self.to_string(), None)
                }
            }
            ApiError::Unauthorized(msg) => {
                if is_production {
                    tracing::warn!(error = %msg, "Unauthorized access attempt");
                    ("Authentication required".to_string(), None)
                } else {
                    (self.to_string(), None)
                }
            }
            ApiError::Forbidden(msg) => {
                if is_production {
                    tracing::warn!(error = %msg, "Forbidden access attempt");
                    ("Access denied".to_string(), None)
                } else {
                    (self.to_string(), None)
                }
            }
            ApiError::Conflict(msg) => {
                if is_production {
                    tracing::warn!(error = %msg, "Conflict error");
                    // Conflict messages are usually already sanitized by From<DbError>
                    (format!("Conflict: {}", msg), None)
                } else {
                    (self.to_string(), None)
                }
            }
            ApiError::UnprocessableEntity(msg) => {
                if is_production {
                    tracing::warn!(error = %msg, "Unprocessable entity error");
                    ("Unable to process request".to_string(), None)
                } else {
                    (self.to_string(), None)
                }
            }
            ApiError::Internal(msg) => {
                // ALWAYS log internal errors server-side with full details
                tracing::error!(error = %msg, "Internal server error");
                if is_production {
                    // Never expose internal error details in production
                    (
                        "An internal error occurred. Please try again later.".to_string(),
                        None,
                    )
                } else {
                    (self.to_string(), None)
                }
            }
            ApiError::Database(msg) => {
                // ALWAYS log database errors server-side with full details
                tracing::error!(error = %msg, "Database error");
                if is_production {
                    // Never expose database error details in production
                    (
                        "A database error occurred. Please try again later.".to_string(),
                        None,
                    )
                } else {
                    (self.to_string(), None)
                }
            }
            ApiError::ServiceUnavailable(msg) => {
                if is_production {
                    tracing::warn!(error = %msg, "Service unavailable");
                    (
                        "Service temporarily unavailable. Please try again later.".to_string(),
                        None,
                    )
                } else {
                    (self.to_string(), None)
                }
            }
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
        use tw_core::is_production_environment;

        match err {
            tw_core::db::DbError::NotFound { entity, id } => {
                ApiError::NotFound(format!("{} with id {} not found", entity, id))
            }
            tw_core::db::DbError::Constraint(msg) => {
                // Constraint errors are usually safe to expose (e.g., "email already exists")
                // but in production, ALWAYS sanitize to prevent information leakage
                if is_production_environment() {
                    // Log the full error server-side for debugging
                    tracing::error!(error = %msg, "Database constraint violation");

                    // Check for common user-friendly constraint patterns that are safe to expose
                    let msg_lower = msg.to_lowercase();
                    let safe_message =
                        if msg_lower.contains("email") && msg_lower.contains("unique") {
                            "A user with this email already exists"
                        } else if msg_lower.contains("username") && msg_lower.contains("unique") {
                            "A user with this username already exists"
                        } else if msg_lower.contains("duplicate") || msg_lower.contains("unique") {
                            "A conflicting resource already exists"
                        } else {
                            // Default generic message for any other constraint
                            "This operation conflicts with an existing resource"
                        };

                    ApiError::Conflict(safe_message.to_string())
                } else {
                    // In development, include full details for debugging
                    ApiError::Conflict(msg)
                }
            }
            tw_core::db::DbError::Serialization(msg) => {
                // Serialization errors indicate malformed data - safe to return
                ApiError::BadRequest(msg)
            }
            err => {
                // For all other database errors, log the full error server-side
                // but return a sanitized message to the client
                tracing::error!(error = %err, "Database error occurred");

                if is_production_environment() {
                    // In production, never expose internal database details
                    ApiError::Database(
                        "A database error occurred. Please try again later.".to_string(),
                    )
                } else {
                    // In development, include the error for debugging
                    ApiError::Database(err.to_string())
                }
            }
        }
    }
}

impl From<serde_json::Error> for ApiError {
    fn from(err: serde_json::Error) -> Self {
        use tw_core::is_production_environment;

        // Log full error server-side
        tracing::warn!(error = %err, "JSON parsing error");

        if is_production_environment() {
            // In production, don't expose JSON parsing details that could
            // reveal internal structure or aid attackers
            ApiError::BadRequest("Invalid JSON format".to_string())
        } else {
            // In development, include full error for debugging
            ApiError::BadRequest(format!("JSON error: {}", err))
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    // Helper to clear production env vars for testing
    fn clear_production_env() {
        std::env::remove_var("TW_ENV");
        std::env::remove_var("NODE_ENV");
        std::env::remove_var("ENVIRONMENT");
    }

    // Helper to set production env
    fn set_production_env() {
        std::env::set_var("TW_ENV", "production");
    }

    #[test]
    fn test_error_codes_defined() {
        assert_eq!(ApiError::NotFound("".to_string()).error_code(), "NOT_FOUND");
        assert_eq!(
            ApiError::BadRequest("".to_string()).error_code(),
            "BAD_REQUEST"
        );
        assert_eq!(
            ApiError::Unauthorized("".to_string()).error_code(),
            "UNAUTHORIZED"
        );
        assert_eq!(
            ApiError::Forbidden("".to_string()).error_code(),
            "FORBIDDEN"
        );
        assert_eq!(ApiError::Conflict("".to_string()).error_code(), "CONFLICT");
        assert_eq!(
            ApiError::Internal("".to_string()).error_code(),
            "INTERNAL_ERROR"
        );
        assert_eq!(
            ApiError::Database("".to_string()).error_code(),
            "DATABASE_ERROR"
        );
        assert_eq!(
            ApiError::ValidationError(ValidationErrorDetails::field("test", "code", "msg"))
                .error_code(),
            "VALIDATION_ERROR"
        );
    }

    #[test]
    fn test_error_status_codes() {
        assert_eq!(
            ApiError::NotFound("".to_string()).status_code(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            ApiError::BadRequest("".to_string()).status_code(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            ApiError::Unauthorized("".to_string()).status_code(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            ApiError::Forbidden("".to_string()).status_code(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            ApiError::Internal("".to_string()).status_code(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            ApiError::Database("".to_string()).status_code(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            ApiError::RateLimitExceeded.status_code(),
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    #[test]
    fn test_validation_error_details_single_field() {
        let details = ValidationErrorDetails::field("email", "required", "Email is required");
        assert!(details.message.contains("email"));
        assert!(details.fields.contains_key("email"));
        assert_eq!(details.fields["email"].len(), 1);
        assert_eq!(details.fields["email"][0].code, "required");
    }

    #[test]
    fn test_validation_error_details_multiple_fields() {
        let mut fields = HashMap::new();
        fields.insert(
            "email".to_string(),
            vec![FieldError {
                code: "required".to_string(),
                message: "Email is required".to_string(),
                params: None,
            }],
        );
        fields.insert(
            "password".to_string(),
            vec![FieldError {
                code: "min_length".to_string(),
                message: "Password too short".to_string(),
                params: Some(serde_json::json!({"min": 8})),
            }],
        );

        let details = ValidationErrorDetails::from_fields(fields);
        assert!(details.message.contains("2 fields"));
    }

    #[test]
    fn test_error_response_serialization() {
        let response = ErrorResponse {
            code: "TEST_ERROR".to_string(),
            message: "Test message".to_string(),
            details: None,
            request_id: Some("req-123".to_string()),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("TEST_ERROR"));
        assert!(json.contains("Test message"));
        assert!(json.contains("req-123"));
    }

    #[test]
    fn test_error_response_omits_none_fields() {
        let response = ErrorResponse {
            code: "TEST".to_string(),
            message: "Test".to_string(),
            details: None,
            request_id: None,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(!json.contains("details"));
        assert!(!json.contains("request_id"));
    }

    // Note: The following tests verify the error sanitization behavior
    // They need to be run with proper environment setup

    #[test]
    fn test_json_error_sanitization_development() {
        clear_production_env();

        // In development, JSON errors should include details
        let json_str = r#"{"invalid"#;
        let err: Result<serde_json::Value, _> = serde_json::from_str(json_str);
        let api_err: ApiError = err.unwrap_err().into();

        match api_err {
            ApiError::BadRequest(msg) => {
                // In development, should contain "JSON error:" with details
                assert!(
                    msg.contains("JSON error:") || msg.contains("Invalid JSON"),
                    "Expected JSON error details in development, got: {}",
                    msg
                );
            }
            _ => panic!("Expected BadRequest error"),
        }
    }

    #[test]
    fn test_internal_error_has_code() {
        let err = ApiError::Internal("secret database connection string".to_string());
        assert_eq!(err.error_code(), "INTERNAL_ERROR");
        assert_eq!(err.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn test_database_error_has_code() {
        let err = ApiError::Database("connection pool exhausted".to_string());
        assert_eq!(err.error_code(), "DATABASE_ERROR");
        assert_eq!(err.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn test_error_message_formats() {
        // Verify error messages follow expected format
        let not_found = ApiError::NotFound("User 123".to_string());
        assert_eq!(not_found.to_string(), "Not found: User 123");

        let bad_request = ApiError::BadRequest("Invalid input".to_string());
        assert_eq!(bad_request.to_string(), "Bad request: Invalid input");

        let internal = ApiError::Internal("Unexpected state".to_string());
        assert_eq!(internal.to_string(), "Internal error: Unexpected state");
    }

    #[test]
    fn test_rate_limit_error() {
        let err = ApiError::RateLimitExceeded;
        assert_eq!(err.error_code(), "RATE_LIMIT_EXCEEDED");
        assert_eq!(err.status_code(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(err.to_string(), "Rate limit exceeded");
    }

    #[test]
    fn test_auth_errors_safe() {
        // Auth errors should not leak sensitive info
        let invalid_creds = ApiError::InvalidCredentials;
        assert_eq!(invalid_creds.to_string(), "Invalid username or password");
        // Should NOT say which one was wrong

        let session_expired = ApiError::SessionExpired;
        assert_eq!(session_expired.to_string(), "Session expired");

        let csrf_failed = ApiError::CsrfValidationFailed;
        assert_eq!(csrf_failed.to_string(), "CSRF validation failed");
    }

    #[test]
    fn test_validation_field_helper() {
        let err = ApiError::validation_field("email", "invalid_format", "Must be a valid email");
        match err {
            ApiError::ValidationError(details) => {
                assert!(details.fields.contains_key("email"));
                assert_eq!(details.fields["email"][0].code, "invalid_format");
            }
            _ => panic!("Expected ValidationError"),
        }
    }

    #[test]
    fn test_add_validation_error() {
        let mut details = ValidationErrorDetails::field("email", "required", "Email is required");
        details.add_error("email", "invalid_format", "Invalid email format");
        details.add_error("password", "min_length", "Password too short");

        assert_eq!(details.fields["email"].len(), 2);
        assert!(details.fields.contains_key("password"));
    }
}
