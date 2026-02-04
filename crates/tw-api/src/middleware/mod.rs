//! HTTP middleware for the API server.
//!
//! This module provides middleware functions and layers for:
//! - Request ID generation and propagation
//! - Request logging with timing
//! - Security headers (CSP, HSTS, etc.)
//! - CORS configuration
//! - Request body size limits
//! - Rate limiting (via rate_limit module)
//! - Tenant resolution (multi-tenancy support)

pub mod tenant;

use axum::{
    extract::Request,
    http::{header, HeaderValue},
    middleware::Next,
    response::Response,
};
use std::time::Instant;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tracing::{info, warn, Span};
use tw_core::is_production_environment;
use uuid::Uuid;

// Re-export tenant middleware components
pub use tenant::{
    create_tenant_resolver, create_tenant_resolver_with_config, tenant_resolution_middleware,
    OptionalTenant, RequireTenant, TenantCache, TenantResolutionConfig, TenantResolutionError,
    TenantResolver, TenantSource, TENANT_ID_HEADER,
};

/// Request ID header name.
pub const REQUEST_ID_HEADER: &str = "X-Request-Id";

/// Middleware to add request ID to requests and responses.
pub async fn request_id(mut request: Request, next: Next) -> Response {
    // Get or generate request ID
    let request_id = request
        .headers()
        .get(REQUEST_ID_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(String::from)
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    // Add to request extensions
    request
        .extensions_mut()
        .insert(RequestId(request_id.clone()));

    // Add to current span
    Span::current().record("request_id", &request_id);

    let mut response = next.run(request).await;

    // Add to response headers
    if let Ok(value) = HeaderValue::from_str(&request_id) {
        response.headers_mut().insert(REQUEST_ID_HEADER, value);
    }

    response
}

/// Request ID extension type.
#[derive(Clone, Debug)]
pub struct RequestId(pub String);

/// Middleware for request logging.
pub async fn request_logging(request: Request, next: Next) -> Response {
    let method = request.method().clone();
    let uri = request.uri().clone();
    let start = Instant::now();

    let request_id = request
        .extensions()
        .get::<RequestId>()
        .map(|r| r.0.clone())
        .unwrap_or_else(|| "unknown".to_string());

    info!(
        request_id = %request_id,
        method = %method,
        uri = %uri,
        "Request started"
    );

    let response = next.run(request).await;

    let duration = start.elapsed();
    let status = response.status();

    if status.is_server_error() {
        warn!(
            request_id = %request_id,
            method = %method,
            uri = %uri,
            status = status.as_u16(),
            duration_ms = duration.as_millis() as u64,
            "Request completed with error"
        );
    } else {
        info!(
            request_id = %request_id,
            method = %method,
            uri = %uri,
            status = status.as_u16(),
            duration_ms = duration.as_millis() as u64,
            "Request completed"
        );
    }

    response
}

/// Default request body size limit (10 MB).
pub const DEFAULT_REQUEST_BODY_LIMIT: usize = 10 * 1024 * 1024;

/// Creates a request body size limit layer.
///
/// The limit can be configured via the `TW_REQUEST_BODY_LIMIT` environment variable
/// (in bytes). Defaults to 10 MB.
pub fn request_body_limit_layer() -> RequestBodyLimitLayer {
    let limit = std::env::var("TW_REQUEST_BODY_LIMIT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_REQUEST_BODY_LIMIT);

    RequestBodyLimitLayer::new(limit)
}

/// Creates the CORS middleware layer.
///
/// Behavior varies based on environment:
///
/// # Production Mode
/// - If `TW_CORS_ALLOWED_ORIGINS` is set, only those origins are allowed
/// - If not set, restricts to same-origin (no CORS headers)
///
/// # Development Mode
/// - If `TW_CORS_ALLOWED_ORIGINS` is set, only those origins are allowed
/// - If not set, allows any origin (permissive for development)
///
/// # Environment Variables
/// - `TW_CORS_ALLOWED_ORIGINS`: Comma-separated list of allowed origins
///   Example: `https://app.example.com,https://admin.example.com`
pub fn cors_layer() -> CorsLayer {
    cors_layer_with_origins(None)
}

/// Creates the CORS middleware layer with explicit origins.
///
/// If `allowed_origins` is provided and non-empty, uses those origins.
/// Otherwise, falls back to environment variable / default behavior.
pub fn cors_layer_with_origins(allowed_origins: Option<&[String]>) -> CorsLayer {
    use axum::http::HeaderName;

    let is_production = is_production_environment();

    // Determine origins from parameter, env var, or defaults
    let origins: Vec<String> = match allowed_origins {
        Some(origins) if !origins.is_empty() => origins.to_vec(),
        _ => std::env::var("TW_CORS_ALLOWED_ORIGINS")
            .map(|v| {
                v.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default(),
    };

    let allow_origin = if !origins.is_empty() {
        // Use configured origins
        let header_values: Vec<HeaderValue> = origins
            .iter()
            .filter_map(|origin| {
                HeaderValue::from_str(origin)
                    .map_err(|e| {
                        warn!(
                            origin = %origin,
                            error = %e,
                            "Invalid CORS origin, skipping"
                        );
                        e
                    })
                    .ok()
            })
            .collect();

        if header_values.is_empty() {
            warn!("No valid CORS origins configured, falling back to restrictive mode");
            AllowOrigin::predicate(|_, _| false)
        } else {
            info!(
                origins = ?origins,
                "CORS configured with allowed origins"
            );
            AllowOrigin::list(header_values)
        }
    } else if is_production {
        // Production: no CORS (same-origin only)
        info!("Production mode: CORS disabled (same-origin only). Set TW_CORS_ALLOWED_ORIGINS to enable cross-origin requests.");
        AllowOrigin::predicate(|_, _| false)
    } else {
        // Development: allow any origin
        info!(
            "Development mode: CORS allowing any origin. Set TW_CORS_ALLOWED_ORIGINS to restrict."
        );
        AllowOrigin::any()
    };

    CorsLayer::new()
        .allow_origin(allow_origin)
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::PUT,
            axum::http::Method::PATCH,
            axum::http::Method::DELETE,
            axum::http::Method::OPTIONS,
        ])
        .allow_headers([
            header::CONTENT_TYPE,
            header::AUTHORIZATION,
            header::ACCEPT,
            HeaderName::from_static("x-request-id"),
            HeaderName::from_static("x-api-key"),
            HeaderName::from_static("x-tenant-id"),
        ])
        .expose_headers([HeaderName::from_static("x-request-id")])
        .max_age(std::time::Duration::from_secs(3600))
}

/// Middleware to add security headers.
pub async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();

    // Prevent MIME type sniffing
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );

    // Prevent clickjacking
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));

    // XSS protection (legacy, but still useful for older browsers)
    headers.insert(
        "X-XSS-Protection",
        HeaderValue::from_static("1; mode=block"),
    );

    // Prevent caching of sensitive responses
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));

    // HTTP Strict Transport Security (HSTS)
    // max-age=31536000 (1 year), includeSubDomains ensures all subdomains use HTTPS
    headers.insert(
        header::STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static("max-age=31536000; includeSubDomains"),
    );

    // Content Security Policy (CSP)
    // Restrictive policy that allows:
    // - Scripts only from self
    // - Styles from self and inline (for HTMX compatibility)
    // - Images from self and data URIs
    // - Connects to self (for API calls)
    // - Frames denied
    // - Reports violations to /api/csp-report (if endpoint exists)
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'self'; \
             script-src 'self'; \
             style-src 'self' 'unsafe-inline'; \
             img-src 'self' data:; \
             font-src 'self'; \
             connect-src 'self'; \
             frame-ancestors 'none'; \
             base-uri 'self'; \
             form-action 'self'",
        ),
    );

    // Referrer Policy - only send origin for cross-origin requests
    headers.insert(
        "Referrer-Policy",
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );

    // Permissions Policy - disable unnecessary browser features
    headers.insert(
        "Permissions-Policy",
        HeaderValue::from_static("geolocation=(), microphone=(), camera=()"),
    );

    response
}
