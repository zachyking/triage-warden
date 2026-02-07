//! Tenant resolution middleware for multi-tenant request handling.
//!
//! This middleware resolves the tenant from incoming HTTP requests using multiple strategies:
//! 1. Subdomain extraction (e.g., `tenant1.example.com` -> `tenant1`)
//! 2. X-Tenant-ID header (UUID format)
//! 3. Optional JWT claim extraction compatibility mode (disabled by default)
//!
//! Resolution order: subdomain > X-Tenant-ID header > default tenant
//! Optional legacy mode: subdomain > X-Tenant-ID header > JWT claim > default tenant
//!
//! # Example
//!
//! ```ignore
//! use tw_api::middleware::tenant::{TenantResolutionLayer, TenantContext};
//!
//! let app = Router::new()
//!     .route("/api/resource", get(handler))
//!     .layer(TenantResolutionLayer::new(tenant_repo));
//!
//! async fn handler(
//!     tenant: TenantContext,
//! ) -> impl IntoResponse {
//!     format!("Hello, tenant {}!", tenant.tenant_slug)
//! }
//! ```

use axum::{
    async_trait,
    extract::{FromRequestParts, Request},
    http::{request::Parts, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use lru::LruCache;
use std::{
    num::NonZeroUsize,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::RwLock;
use tracing::{debug, info, warn, Span};
use tw_core::{
    db::{create_tenant_repository, DbPool},
    tenant::{Tenant, TenantContext, TenantStatus},
};
use uuid::Uuid;

/// Header name for explicit tenant ID specification.
pub const TENANT_ID_HEADER: &str = "X-Tenant-ID";

/// Paths that bypass tenant resolution.
const BYPASS_PATHS: &[&str] = &[
    "/health",
    "/ready",
    "/live",
    "/metrics",
    "/api-docs",
    "/swagger-ui",
];

/// Default cache TTL in seconds.
const DEFAULT_CACHE_TTL_SECS: u64 = 60;

/// Default cache capacity.
const DEFAULT_CACHE_CAPACITY: usize = 1000;

/// Cached tenant entry with TTL.
#[derive(Clone)]
struct CachedTenant {
    tenant: Tenant,
    cached_at: Instant,
}

impl CachedTenant {
    fn new(tenant: Tenant) -> Self {
        Self {
            tenant,
            cached_at: Instant::now(),
        }
    }

    fn is_expired(&self, ttl: Duration) -> bool {
        self.cached_at.elapsed() > ttl
    }
}

/// Tenant cache with configurable TTL and capacity.
pub struct TenantCache {
    /// Cache for tenant slug -> tenant mapping.
    by_slug: RwLock<LruCache<String, CachedTenant>>,
    /// Cache for tenant ID -> tenant mapping.
    by_id: RwLock<LruCache<Uuid, CachedTenant>>,
    /// Cache TTL.
    ttl: Duration,
}

impl TenantCache {
    /// Creates a new tenant cache with the given capacity and TTL.
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        let cap = NonZeroUsize::new(capacity).unwrap_or(NonZeroUsize::new(1).unwrap());
        Self {
            by_slug: RwLock::new(LruCache::new(cap)),
            by_id: RwLock::new(LruCache::new(cap)),
            ttl,
        }
    }

    /// Creates a new tenant cache with default settings.
    pub fn default_cache() -> Self {
        Self::new(
            DEFAULT_CACHE_CAPACITY,
            Duration::from_secs(DEFAULT_CACHE_TTL_SECS),
        )
    }

    /// Gets a tenant by slug from cache if present and not expired.
    async fn get_by_slug(&self, slug: &str) -> Option<Tenant> {
        let mut cache = self.by_slug.write().await;
        if let Some(cached) = cache.get(slug) {
            if !cached.is_expired(self.ttl) {
                return Some(cached.tenant.clone());
            }
            // Remove expired entry
            cache.pop(slug);
        }
        None
    }

    /// Gets a tenant by ID from cache if present and not expired.
    async fn get_by_id(&self, id: Uuid) -> Option<Tenant> {
        let mut cache = self.by_id.write().await;
        if let Some(cached) = cache.get(&id) {
            if !cached.is_expired(self.ttl) {
                return Some(cached.tenant.clone());
            }
            // Remove expired entry
            cache.pop(&id);
        }
        None
    }

    /// Inserts a tenant into both caches.
    async fn insert(&self, tenant: &Tenant) {
        let cached = CachedTenant::new(tenant.clone());
        {
            let mut by_slug = self.by_slug.write().await;
            by_slug.put(tenant.slug.clone(), cached.clone());
        }
        {
            let mut by_id = self.by_id.write().await;
            by_id.put(tenant.id, cached);
        }
    }

    /// Invalidates a tenant from both caches.
    #[allow(dead_code)]
    pub async fn invalidate(&self, tenant_id: Uuid, slug: &str) {
        {
            let mut by_slug = self.by_slug.write().await;
            by_slug.pop(slug);
        }
        {
            let mut by_id = self.by_id.write().await;
            by_id.pop(&tenant_id);
        }
    }
}

/// Source of tenant resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantSource {
    /// Resolved from subdomain.
    Subdomain,
    /// Resolved from X-Tenant-ID header.
    Header,
    /// Resolved from JWT claim.
    JwtClaim,
    /// Default tenant (for single-tenant deployments).
    Default,
}

/// Error type for tenant resolution failures.
#[derive(Debug)]
pub enum TenantResolutionError {
    /// Tenant not found (returns 404 to avoid leaking tenant existence).
    NotFound,
    /// Tenant is suspended or not operational.
    NotOperational(TenantStatus),
    /// Internal error during resolution.
    Internal(String),
}

impl IntoResponse for TenantResolutionError {
    fn into_response(self) -> Response {
        // Return 404 for all tenant resolution errors to avoid leaking tenant existence
        // This is a security measure to prevent tenant enumeration attacks
        match self {
            TenantResolutionError::NotFound => (StatusCode::NOT_FOUND, "Not Found").into_response(),
            TenantResolutionError::NotOperational(_) => {
                // Don't leak that the tenant exists but is suspended
                (StatusCode::NOT_FOUND, "Not Found").into_response()
            }
            TenantResolutionError::Internal(msg) => {
                warn!(error = %msg, "Internal tenant resolution error");
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error").into_response()
            }
        }
    }
}

/// Configuration for tenant resolution middleware.
#[derive(Clone)]
pub struct TenantResolutionConfig {
    /// Whether to require tenant resolution (false allows requests without tenant).
    pub require_tenant: bool,
    /// Base domain for subdomain extraction (e.g., "example.com").
    pub base_domain: Option<String>,
    /// Default tenant slug for single-tenant deployments.
    pub default_tenant_slug: Option<String>,
    /// Cache TTL in seconds.
    pub cache_ttl_secs: u64,
    /// Cache capacity.
    pub cache_capacity: usize,
}

impl Default for TenantResolutionConfig {
    fn default() -> Self {
        Self {
            require_tenant: true,
            base_domain: std::env::var("TW_BASE_DOMAIN").ok(),
            default_tenant_slug: std::env::var("TW_DEFAULT_TENANT").ok(),
            cache_ttl_secs: std::env::var("TW_TENANT_CACHE_TTL_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(DEFAULT_CACHE_TTL_SECS),
            cache_capacity: std::env::var("TW_TENANT_CACHE_CAPACITY")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(DEFAULT_CACHE_CAPACITY),
        }
    }
}

/// Tenant resolver that handles tenant lookup with caching.
#[derive(Clone)]
pub struct TenantResolver {
    db: Arc<DbPool>,
    cache: Arc<TenantCache>,
    config: TenantResolutionConfig,
}

impl TenantResolver {
    /// Creates a new tenant resolver.
    pub fn new(db: Arc<DbPool>, config: TenantResolutionConfig) -> Self {
        let cache = Arc::new(TenantCache::new(
            config.cache_capacity,
            Duration::from_secs(config.cache_ttl_secs),
        ));
        Self { db, cache, config }
    }

    /// Creates a tenant resolver with default config.
    pub fn with_defaults(db: Arc<DbPool>) -> Self {
        Self::new(db, TenantResolutionConfig::default())
    }

    /// Resolves tenant from request.
    ///
    /// Resolution order: subdomain > X-Tenant-ID header > default
    /// Optional legacy mode: enable `TW_ALLOW_UNVERIFIED_JWT_TENANT=true`
    /// to allow unverified JWT claim extraction before default tenant.
    pub async fn resolve(
        &self,
        headers: &HeaderMap,
        path: &str,
    ) -> Result<Option<(TenantContext, TenantSource)>, TenantResolutionError> {
        // Check if path should bypass tenant resolution
        if should_bypass_path(path) {
            debug!(path = %path, "Bypassing tenant resolution for path");
            return Ok(None);
        }

        // Try subdomain extraction
        if let Some(slug) = self.extract_subdomain(headers) {
            debug!(slug = %slug, "Extracted tenant slug from subdomain");
            return self
                .resolve_by_slug(&slug)
                .await
                .map(|ctx| Some((ctx, TenantSource::Subdomain)));
        }

        // Try X-Tenant-ID header
        if let Some(tenant_id) = self.extract_header_tenant_id(headers) {
            debug!(tenant_id = %tenant_id, "Extracted tenant ID from header");
            return self
                .resolve_by_id(tenant_id)
                .await
                .map(|ctx| Some((ctx, TenantSource::Header)));
        }

        // Optional legacy behavior: extract tenant from an unverified JWT claim.
        // This is intentionally disabled by default because claims are parsed
        // before signature verification in this middleware.
        let allow_unverified_jwt_tenant = std::env::var("TW_ALLOW_UNVERIFIED_JWT_TENANT")
            .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
            .unwrap_or(false);
        if allow_unverified_jwt_tenant {
            if let Some(tenant_id) = self.extract_jwt_tenant_id(headers) {
                debug!(tenant_id = %tenant_id, "Extracted tenant ID from JWT claim");
                return self
                    .resolve_by_id(tenant_id)
                    .await
                    .map(|ctx| Some((ctx, TenantSource::JwtClaim)));
            }
        }

        // Try default tenant
        if let Some(ref default_slug) = self.config.default_tenant_slug {
            debug!(slug = %default_slug, "Using default tenant");
            return self
                .resolve_by_slug(default_slug)
                .await
                .map(|ctx| Some((ctx, TenantSource::Default)));
        }

        // No tenant found
        if self.config.require_tenant {
            Err(TenantResolutionError::NotFound)
        } else {
            Ok(None)
        }
    }

    /// Extracts tenant slug from subdomain.
    fn extract_subdomain(&self, headers: &HeaderMap) -> Option<String> {
        let base_domain = self.config.base_domain.as_ref()?;

        let host = headers
            .get(axum::http::header::HOST)
            .and_then(|h| h.to_str().ok())?;

        // Remove port if present
        let host = host.split(':').next()?;

        // Check if host ends with base domain
        if !host.ends_with(base_domain) {
            return None;
        }

        // Extract subdomain
        let subdomain = host.strip_suffix(base_domain)?.trim_end_matches('.');

        // Validate subdomain is not empty and doesn't contain dots (no nested subdomains)
        if subdomain.is_empty() || subdomain.contains('.') {
            return None;
        }

        // Skip common non-tenant subdomains
        if matches!(
            subdomain,
            "www" | "api" | "admin" | "app" | "dashboard" | "static" | "cdn" | "assets"
        ) {
            return None;
        }

        Some(subdomain.to_string())
    }

    /// Extracts tenant ID from X-Tenant-ID header.
    fn extract_header_tenant_id(&self, headers: &HeaderMap) -> Option<Uuid> {
        headers
            .get(TENANT_ID_HEADER)
            .and_then(|h| h.to_str().ok())
            .and_then(|s| Uuid::parse_str(s).ok())
    }

    /// Extracts tenant ID from JWT Authorization header.
    fn extract_jwt_tenant_id(&self, headers: &HeaderMap) -> Option<Uuid> {
        let auth_header = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())?;

        let token = auth_header.strip_prefix("Bearer ")?;

        // Simple JWT parsing - extract payload without verification
        // The actual JWT verification happens in the auth middleware
        // We just need to extract the tenant_id claim if present
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return None;
        }

        // Decode base64 payload (URL-safe base64 without padding)
        let payload = base64_decode_url_safe(parts[1])?;
        let claims: serde_json::Value = serde_json::from_slice(&payload).ok()?;

        // Extract tenant_id from claims
        claims
            .get("tenant_id")
            .and_then(|v| v.as_str())
            .and_then(|s| Uuid::parse_str(s).ok())
    }

    /// Resolves tenant by slug.
    async fn resolve_by_slug(&self, slug: &str) -> Result<TenantContext, TenantResolutionError> {
        // Check cache first
        if let Some(tenant) = self.cache.get_by_slug(slug).await {
            return self.tenant_to_context(tenant);
        }

        // Query database
        let repo = create_tenant_repository(&self.db);
        let tenant = repo
            .get_by_slug(slug)
            .await
            .map_err(|e| TenantResolutionError::Internal(e.to_string()))?
            .ok_or(TenantResolutionError::NotFound)?;

        // Cache the result
        self.cache.insert(&tenant).await;

        self.tenant_to_context(tenant)
    }

    /// Resolves tenant by ID.
    async fn resolve_by_id(&self, id: Uuid) -> Result<TenantContext, TenantResolutionError> {
        // Check cache first
        if let Some(tenant) = self.cache.get_by_id(id).await {
            return self.tenant_to_context(tenant);
        }

        // Query database
        let repo = create_tenant_repository(&self.db);
        let tenant = repo
            .get(id)
            .await
            .map_err(|e| TenantResolutionError::Internal(e.to_string()))?
            .ok_or(TenantResolutionError::NotFound)?;

        // Cache the result
        self.cache.insert(&tenant).await;

        self.tenant_to_context(tenant)
    }

    /// Converts a Tenant to TenantContext, checking operational status.
    fn tenant_to_context(&self, tenant: Tenant) -> Result<TenantContext, TenantResolutionError> {
        if !tenant.is_operational() {
            return Err(TenantResolutionError::NotOperational(tenant.status));
        }
        Ok(TenantContext::from_tenant(&tenant))
    }
}

/// Checks if a path should bypass tenant resolution.
fn should_bypass_path(path: &str) -> bool {
    BYPASS_PATHS
        .iter()
        .any(|bypass| path.starts_with(bypass) || path == *bypass)
}

/// Decodes URL-safe base64 (without padding).
fn base64_decode_url_safe(input: &str) -> Option<Vec<u8>> {
    // Add padding if needed
    let padding = match input.len() % 4 {
        2 => "==",
        3 => "=",
        _ => "",
    };
    let padded = format!("{}{}", input, padding);

    // Convert from URL-safe to standard base64
    let standard: String = padded
        .chars()
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            c => c,
        })
        .collect();

    // We need to use a simple base64 decoder
    // Using a simple implementation since we don't have base64 crate
    simple_base64_decode(&standard)
}

/// Simple base64 decoder.
fn simple_base64_decode(input: &str) -> Option<Vec<u8>> {
    const DECODE_TABLE: &[u8; 256] = &{
        let mut table = [255u8; 256];
        let chars = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut i = 0;
        while i < 64 {
            table[chars[i] as usize] = i as u8;
            i += 1;
        }
        table
    };

    let input = input.as_bytes();
    let mut output = Vec::with_capacity(input.len() * 3 / 4);

    let mut i = 0;
    while i + 3 < input.len() {
        let a = DECODE_TABLE[input[i] as usize];
        let b = DECODE_TABLE[input[i + 1] as usize];
        let c = DECODE_TABLE[input[i + 2] as usize];
        let d = DECODE_TABLE[input[i + 3] as usize];

        if a == 255 || b == 255 {
            return None;
        }

        output.push((a << 2) | (b >> 4));

        if input[i + 2] != b'=' {
            if c == 255 {
                return None;
            }
            output.push((b << 4) | (c >> 2));
        }

        if input[i + 3] != b'=' {
            if d == 255 {
                return None;
            }
            output.push((c << 6) | d);
        }

        i += 4;
    }

    Some(output)
}

/// Axum extractor for TenantContext.
///
/// This extractor retrieves the tenant context from request extensions.
/// The context must be set by the tenant resolution middleware.
///
/// # Example
///
/// ```ignore
/// async fn handler(
///     RequireTenant(tenant): RequireTenant,
/// ) -> impl IntoResponse {
///     format!("Tenant: {}", tenant.tenant_slug)
/// }
/// ```
pub struct RequireTenant(pub TenantContext);

#[async_trait]
impl<S> FromRequestParts<S> for RequireTenant
where
    S: Send + Sync,
{
    type Rejection = TenantResolutionError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<TenantContext>()
            .cloned()
            .map(RequireTenant)
            .ok_or(TenantResolutionError::NotFound)
    }
}

/// Optional tenant context extractor.
///
/// Returns `None` if no tenant context is set (e.g., for public endpoints).
pub struct OptionalTenant(pub Option<TenantContext>);

#[async_trait]
impl<S> FromRequestParts<S> for OptionalTenant
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(OptionalTenant(
            parts.extensions.get::<TenantContext>().cloned(),
        ))
    }
}

/// Middleware function for tenant resolution.
///
/// This should be added to the middleware stack to resolve tenants for all requests.
pub async fn tenant_resolution_middleware(
    resolver: TenantResolver,
    mut request: Request,
) -> Result<Request, Response> {
    let path = request.uri().path().to_string();
    let headers = request.headers().clone();

    match resolver.resolve(&headers, &path).await {
        Ok(Some((context, source))) => {
            // Add tenant context to request extensions
            request.extensions_mut().insert(context.clone());

            // Record tenant info in tracing span
            Span::current().record("tenant_id", context.tenant_id.to_string());
            Span::current().record("tenant_slug", &context.tenant_slug);

            info!(
                tenant_id = %context.tenant_id,
                tenant_slug = %context.tenant_slug,
                source = ?source,
                "Tenant resolved"
            );

            Ok(request)
        }
        Ok(None) => {
            // No tenant required or bypass path
            debug!(path = %path, "Request proceeding without tenant context");
            Ok(request)
        }
        Err(e) => {
            warn!(path = %path, error = ?e, "Tenant resolution failed");
            Err(e.into_response())
        }
    }
}

/// Creates the tenant resolution middleware layer.
///
/// # Example
///
/// ```ignore
/// use axum::{Router, middleware};
/// use tw_api::middleware::tenant::create_tenant_middleware;
///
/// let app = Router::new()
///     .route("/api/resource", get(handler))
///     .layer(middleware::from_fn_with_state(
///         resolver,
///         |resolver, req, next| async move {
///             let req = tenant_resolution_middleware(resolver, req).await?;
///             Ok(next.run(req).await)
///         }
///     ));
/// ```
pub fn create_tenant_resolver(db: Arc<DbPool>) -> TenantResolver {
    TenantResolver::with_defaults(db)
}

/// Creates a tenant resolver with custom configuration.
pub fn create_tenant_resolver_with_config(
    db: Arc<DbPool>,
    config: TenantResolutionConfig,
) -> TenantResolver {
    TenantResolver::new(db, config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn test_should_bypass_path() {
        assert!(should_bypass_path("/health"));
        assert!(should_bypass_path("/health/detailed"));
        assert!(should_bypass_path("/ready"));
        assert!(should_bypass_path("/live"));
        assert!(should_bypass_path("/metrics"));
        assert!(should_bypass_path("/api-docs"));
        assert!(should_bypass_path("/swagger-ui"));

        assert!(!should_bypass_path("/api/v1/incidents"));
        assert!(!should_bypass_path("/api/v1/users"));
        assert!(!should_bypass_path("/"));
    }

    #[tokio::test]
    async fn test_extract_subdomain() {
        let pool = sqlx::sqlite::SqlitePool::connect("sqlite::memory:")
            .await
            .unwrap();
        let config = TenantResolutionConfig {
            base_domain: Some("example.com".to_string()),
            ..Default::default()
        };
        let resolver = TenantResolver {
            db: Arc::new(tw_core::db::DbPool::Sqlite(pool)),
            cache: Arc::new(TenantCache::default_cache()),
            config,
        };

        // Valid subdomain
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::HOST,
            HeaderValue::from_static("acme.example.com"),
        );
        assert_eq!(
            resolver.extract_subdomain(&headers),
            Some("acme".to_string())
        );

        // Valid subdomain with port
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::HOST,
            HeaderValue::from_static("tenant1.example.com:8080"),
        );
        assert_eq!(
            resolver.extract_subdomain(&headers),
            Some("tenant1".to_string())
        );

        // Base domain only (no subdomain)
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::HOST,
            HeaderValue::from_static("example.com"),
        );
        assert_eq!(resolver.extract_subdomain(&headers), None);

        // www subdomain (should be skipped)
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::HOST,
            HeaderValue::from_static("www.example.com"),
        );
        assert_eq!(resolver.extract_subdomain(&headers), None);

        // api subdomain (should be skipped)
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::HOST,
            HeaderValue::from_static("api.example.com"),
        );
        assert_eq!(resolver.extract_subdomain(&headers), None);

        // Nested subdomain (should be skipped)
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::HOST,
            HeaderValue::from_static("sub.tenant.example.com"),
        );
        assert_eq!(resolver.extract_subdomain(&headers), None);

        // Different domain (should be skipped)
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::HOST,
            HeaderValue::from_static("tenant.other.com"),
        );
        assert_eq!(resolver.extract_subdomain(&headers), None);
    }

    #[tokio::test]
    async fn test_extract_header_tenant_id() {
        let pool = sqlx::sqlite::SqlitePool::connect("sqlite::memory:")
            .await
            .unwrap();
        let config = TenantResolutionConfig::default();
        let resolver = TenantResolver {
            db: Arc::new(tw_core::db::DbPool::Sqlite(pool)),
            cache: Arc::new(TenantCache::default_cache()),
            config,
        };

        // Valid UUID header
        let tenant_id = Uuid::new_v4();
        let mut headers = HeaderMap::new();
        headers.insert(
            TENANT_ID_HEADER,
            HeaderValue::from_str(&tenant_id.to_string()).unwrap(),
        );
        assert_eq!(resolver.extract_header_tenant_id(&headers), Some(tenant_id));

        // Invalid UUID header
        let mut headers = HeaderMap::new();
        headers.insert(TENANT_ID_HEADER, HeaderValue::from_static("not-a-uuid"));
        assert_eq!(resolver.extract_header_tenant_id(&headers), None);

        // No header
        let headers = HeaderMap::new();
        assert_eq!(resolver.extract_header_tenant_id(&headers), None);
    }

    #[test]
    fn test_base64_decode() {
        // Test standard JWT payload decoding
        // {"sub":"1234567890","name":"John Doe","tenant_id":"550e8400-e29b-41d4-a716-446655440000"}
        let payload = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwidGVuYW50X2lkIjoiNTUwZTg0MDAtZTI5Yi00MWQ0LWE3MTYtNDQ2NjU1NDQwMDAwIn0";
        let decoded = base64_decode_url_safe(payload).expect("Should decode");
        let json: serde_json::Value = serde_json::from_slice(&decoded).expect("Should parse JSON");

        assert_eq!(json["sub"], "1234567890");
        assert_eq!(json["tenant_id"], "550e8400-e29b-41d4-a716-446655440000");
    }

    #[test]
    fn test_tenant_cache() {
        use tokio::runtime::Runtime;

        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let cache = TenantCache::new(10, Duration::from_secs(60));

            let tenant = Tenant::new("test-tenant", "Test Tenant").unwrap();
            let tenant_id = tenant.id;
            let tenant_slug = tenant.slug.clone();

            // Insert and retrieve by slug
            cache.insert(&tenant).await;
            let retrieved = cache.get_by_slug(&tenant_slug).await;
            assert!(retrieved.is_some());
            assert_eq!(retrieved.unwrap().id, tenant_id);

            // Retrieve by ID
            let retrieved = cache.get_by_id(tenant_id).await;
            assert!(retrieved.is_some());
            assert_eq!(retrieved.unwrap().slug, tenant_slug);

            // Invalidate
            cache.invalidate(tenant_id, &tenant_slug).await;
            assert!(cache.get_by_slug(&tenant_slug).await.is_none());
            assert!(cache.get_by_id(tenant_id).await.is_none());
        });
    }

    #[test]
    fn test_tenant_cache_expiry() {
        use tokio::runtime::Runtime;

        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            // Short TTL for testing
            let cache = TenantCache::new(10, Duration::from_millis(50));

            let tenant = Tenant::new("test-tenant", "Test Tenant").unwrap();
            let tenant_slug = tenant.slug.clone();

            cache.insert(&tenant).await;

            // Should be in cache
            assert!(cache.get_by_slug(&tenant_slug).await.is_some());

            // Wait for expiry
            tokio::time::sleep(Duration::from_millis(100)).await;

            // Should be expired and removed
            assert!(cache.get_by_slug(&tenant_slug).await.is_none());
        });
    }

    #[test]
    fn test_tenant_resolution_error_response() {
        let not_found = TenantResolutionError::NotFound;
        let response = not_found.into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let not_operational = TenantResolutionError::NotOperational(TenantStatus::Suspended);
        let response = not_operational.into_response();
        // Should still return 404 to avoid leaking tenant existence
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let internal = TenantResolutionError::Internal("test error".to_string());
        let response = internal.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    // ============================================================
    // Invalid Tenant ID Format Tests
    // ============================================================

    #[tokio::test]
    async fn test_extract_header_tenant_id_various_invalid_formats() {
        let pool = sqlx::sqlite::SqlitePool::connect("sqlite::memory:")
            .await
            .unwrap();
        let config = TenantResolutionConfig::default();
        let resolver = TenantResolver {
            db: Arc::new(tw_core::db::DbPool::Sqlite(pool)),
            cache: Arc::new(TenantCache::default_cache()),
            config,
        };

        // Empty string
        let mut headers = HeaderMap::new();
        headers.insert(TENANT_ID_HEADER, HeaderValue::from_static(""));
        assert_eq!(resolver.extract_header_tenant_id(&headers), None);

        // Plain text (not UUID)
        let mut headers = HeaderMap::new();
        headers.insert(TENANT_ID_HEADER, HeaderValue::from_static("my-tenant"));
        assert_eq!(resolver.extract_header_tenant_id(&headers), None);

        // UUID-like but wrong length
        let mut headers = HeaderMap::new();
        headers.insert(
            TENANT_ID_HEADER,
            HeaderValue::from_static("550e8400-e29b-41d4-a716"),
        );
        assert_eq!(resolver.extract_header_tenant_id(&headers), None);

        // Numeric value
        let mut headers = HeaderMap::new();
        headers.insert(TENANT_ID_HEADER, HeaderValue::from_static("12345"));
        assert_eq!(resolver.extract_header_tenant_id(&headers), None);

        // UUID with extra characters
        let mut headers = HeaderMap::new();
        headers.insert(
            TENANT_ID_HEADER,
            HeaderValue::from_static("550e8400-e29b-41d4-a716-446655440000-extra"),
        );
        assert_eq!(resolver.extract_header_tenant_id(&headers), None);
    }

    // ============================================================
    // Subdomain Edge Cases
    // ============================================================

    #[tokio::test]
    async fn test_extract_subdomain_no_base_domain_configured() {
        let pool = sqlx::sqlite::SqlitePool::connect("sqlite::memory:")
            .await
            .unwrap();
        let config = TenantResolutionConfig {
            base_domain: None,
            ..Default::default()
        };
        let resolver = TenantResolver {
            db: Arc::new(tw_core::db::DbPool::Sqlite(pool)),
            cache: Arc::new(TenantCache::default_cache()),
            config,
        };

        // With no base domain configured, subdomain extraction should return None
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::HOST,
            HeaderValue::from_static("tenant.example.com"),
        );
        assert_eq!(resolver.extract_subdomain(&headers), None);
    }

    #[tokio::test]
    async fn test_extract_subdomain_no_host_header() {
        let pool = sqlx::sqlite::SqlitePool::connect("sqlite::memory:")
            .await
            .unwrap();
        let config = TenantResolutionConfig {
            base_domain: Some("example.com".to_string()),
            ..Default::default()
        };
        let resolver = TenantResolver {
            db: Arc::new(tw_core::db::DbPool::Sqlite(pool)),
            cache: Arc::new(TenantCache::default_cache()),
            config,
        };

        // No Host header at all
        let headers = HeaderMap::new();
        assert_eq!(resolver.extract_subdomain(&headers), None);
    }

    #[tokio::test]
    async fn test_extract_subdomain_all_reserved_subdomains() {
        let pool = sqlx::sqlite::SqlitePool::connect("sqlite::memory:")
            .await
            .unwrap();
        let config = TenantResolutionConfig {
            base_domain: Some("example.com".to_string()),
            ..Default::default()
        };
        let resolver = TenantResolver {
            db: Arc::new(tw_core::db::DbPool::Sqlite(pool)),
            cache: Arc::new(TenantCache::default_cache()),
            config,
        };

        let reserved = &[
            "www",
            "api",
            "admin",
            "app",
            "dashboard",
            "static",
            "cdn",
            "assets",
        ];
        for sub in reserved {
            let mut headers = HeaderMap::new();
            let host = format!("{}.example.com", sub);
            headers.insert(
                axum::http::header::HOST,
                HeaderValue::from_str(&host).unwrap(),
            );
            assert_eq!(
                resolver.extract_subdomain(&headers),
                None,
                "Reserved subdomain '{}' should not be extracted",
                sub
            );
        }
    }

    #[tokio::test]
    async fn test_extract_subdomain_host_is_just_port() {
        let pool = sqlx::sqlite::SqlitePool::connect("sqlite::memory:")
            .await
            .unwrap();
        let config = TenantResolutionConfig {
            base_domain: Some("example.com".to_string()),
            ..Default::default()
        };
        let resolver = TenantResolver {
            db: Arc::new(tw_core::db::DbPool::Sqlite(pool)),
            cache: Arc::new(TenantCache::default_cache()),
            config,
        };

        // Host with just port number
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::HOST,
            HeaderValue::from_static("example.com:443"),
        );
        assert_eq!(resolver.extract_subdomain(&headers), None);
    }

    // ============================================================
    // Bypass Path Edge Cases
    // ============================================================

    #[test]
    fn test_should_bypass_path_edge_cases() {
        // Path prefix matching - these all start with a bypass prefix
        assert!(should_bypass_path("/health/"));
        assert!(should_bypass_path("/health/detailed"));
        assert!(should_bypass_path("/metrics/prometheus"));
        assert!(should_bypass_path("/swagger-ui/index.html"));

        // /healthz also matches because /health is a prefix
        assert!(should_bypass_path("/healthz"));

        // Should NOT bypass
        assert!(!should_bypass_path("/api/health")); // health is not at the root
        assert!(!should_bypass_path("/v1/metrics"));
        assert!(!should_bypass_path(""));
        assert!(!should_bypass_path("/dashboard"));
        assert!(!should_bypass_path("/api/v1/incidents"));
    }

    // ============================================================
    // Tenant Resolution Error Edge Cases
    // ============================================================

    #[test]
    fn test_tenant_resolution_error_pending_deletion_status() {
        let not_operational = TenantResolutionError::NotOperational(TenantStatus::PendingDeletion);
        let response = not_operational.into_response();
        // Should return 404 to avoid leaking tenant existence
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    // ============================================================
    // Base64 Decode Edge Cases
    // ============================================================

    #[test]
    fn test_base64_decode_empty_input() {
        let result = base64_decode_url_safe("");
        // Empty input should decode to empty output
        assert!(result.is_some());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_base64_decode_invalid_characters() {
        // Characters outside the base64 alphabet
        let result = base64_decode_url_safe("!!!!");
        assert!(result.is_none());
    }

    #[test]
    fn test_base64_decode_url_safe_characters() {
        // URL-safe base64 uses - and _ instead of + and /
        // "Hello" in URL-safe base64 is SGVsbG8
        let result = base64_decode_url_safe("SGVsbG8");
        assert!(result.is_some());
        let decoded = String::from_utf8(result.unwrap()).unwrap();
        assert_eq!(decoded, "Hello");
    }

    // ============================================================
    // JWT Extraction Tests
    // ============================================================

    #[tokio::test]
    async fn test_extract_jwt_tenant_id_no_auth_header() {
        let pool = sqlx::sqlite::SqlitePool::connect("sqlite::memory:")
            .await
            .unwrap();
        let config = TenantResolutionConfig::default();
        let resolver = TenantResolver {
            db: Arc::new(tw_core::db::DbPool::Sqlite(pool)),
            cache: Arc::new(TenantCache::default_cache()),
            config,
        };

        let headers = HeaderMap::new();
        assert_eq!(resolver.extract_jwt_tenant_id(&headers), None);
    }

    #[tokio::test]
    async fn test_extract_jwt_tenant_id_non_bearer_auth() {
        let pool = sqlx::sqlite::SqlitePool::connect("sqlite::memory:")
            .await
            .unwrap();
        let config = TenantResolutionConfig::default();
        let resolver = TenantResolver {
            db: Arc::new(tw_core::db::DbPool::Sqlite(pool)),
            cache: Arc::new(TenantCache::default_cache()),
            config,
        };

        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Basic dXNlcjpwYXNz"),
        );
        assert_eq!(resolver.extract_jwt_tenant_id(&headers), None);
    }

    #[tokio::test]
    async fn test_extract_jwt_tenant_id_malformed_token() {
        let pool = sqlx::sqlite::SqlitePool::connect("sqlite::memory:")
            .await
            .unwrap();
        let config = TenantResolutionConfig::default();
        let resolver = TenantResolver {
            db: Arc::new(tw_core::db::DbPool::Sqlite(pool)),
            cache: Arc::new(TenantCache::default_cache()),
            config,
        };

        // Token with only 2 parts (missing signature)
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer header.payload"),
        );
        assert_eq!(resolver.extract_jwt_tenant_id(&headers), None);

        // Token with 4 parts
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer a.b.c.d"),
        );
        assert_eq!(resolver.extract_jwt_tenant_id(&headers), None);

        // Token with no dots
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer nodots"),
        );
        assert_eq!(resolver.extract_jwt_tenant_id(&headers), None);
    }

    #[tokio::test]
    async fn test_extract_jwt_tenant_id_no_tenant_claim() {
        let pool = sqlx::sqlite::SqlitePool::connect("sqlite::memory:")
            .await
            .unwrap();
        let config = TenantResolutionConfig::default();
        let resolver = TenantResolver {
            db: Arc::new(tw_core::db::DbPool::Sqlite(pool)),
            cache: Arc::new(TenantCache::default_cache()),
            config,
        };

        // JWT with no tenant_id claim: {"sub":"user123"}
        // header: eyJhbGciOiJIUzI1NiJ9 payload: eyJzdWIiOiJ1c2VyMTIzIn0 sig: fake
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.fakesig"),
        );
        assert_eq!(resolver.extract_jwt_tenant_id(&headers), None);
    }

    // ============================================================
    // TenantCache Edge Cases
    // ============================================================

    #[test]
    fn test_tenant_cache_overwrite() {
        use tokio::runtime::Runtime;

        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let cache = TenantCache::new(10, Duration::from_secs(60));

            let tenant1 = Tenant::new("test-slug", "First Name").unwrap();
            let tenant1_id = tenant1.id;
            cache.insert(&tenant1).await;

            // Insert another tenant with same slug (overwrites)
            let tenant2 = Tenant::new("test-slug", "Second Name").unwrap();
            // tenant2 will have a different ID by default
            let tenant2_id = tenant2.id;
            cache.insert(&tenant2).await;

            // By slug, should return the newer one
            let retrieved = cache.get_by_slug("test-slug").await.unwrap();
            assert_eq!(retrieved.id, tenant2_id);
            assert_eq!(retrieved.name, "Second Name");

            // Old ID should still be in the by_id cache
            let old = cache.get_by_id(tenant1_id).await;
            assert!(old.is_some());
        });
    }

    #[test]
    fn test_tenant_cache_capacity_eviction() {
        use tokio::runtime::Runtime;

        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            // Cache with capacity of 2
            let cache = TenantCache::new(2, Duration::from_secs(60));

            let t1 = Tenant::new("slug-1", "Tenant 1").unwrap();
            let t2 = Tenant::new("slug-2", "Tenant 2").unwrap();
            let t3 = Tenant::new("slug-3", "Tenant 3").unwrap();

            cache.insert(&t1).await;
            cache.insert(&t2).await;
            cache.insert(&t3).await; // Should evict t1 (LRU)

            // t1 should be evicted from slug cache
            assert!(cache.get_by_slug("slug-1").await.is_none());
            // t2 and t3 should still be present
            assert!(cache.get_by_slug("slug-2").await.is_some());
            assert!(cache.get_by_slug("slug-3").await.is_some());
        });
    }

    // ============================================================
    // TenantResolutionConfig Tests
    // ============================================================

    #[test]
    fn test_tenant_resolution_config_defaults() {
        // Clear env vars that might affect defaults
        let config = TenantResolutionConfig {
            require_tenant: true,
            base_domain: None,
            default_tenant_slug: None,
            cache_ttl_secs: DEFAULT_CACHE_TTL_SECS,
            cache_capacity: DEFAULT_CACHE_CAPACITY,
        };

        assert!(config.require_tenant);
        assert!(config.base_domain.is_none());
        assert!(config.default_tenant_slug.is_none());
        assert_eq!(config.cache_ttl_secs, 60);
        assert_eq!(config.cache_capacity, 1000);
    }

    #[test]
    fn test_tenant_source_equality() {
        assert_eq!(TenantSource::Subdomain, TenantSource::Subdomain);
        assert_eq!(TenantSource::Header, TenantSource::Header);
        assert_eq!(TenantSource::JwtClaim, TenantSource::JwtClaim);
        assert_eq!(TenantSource::Default, TenantSource::Default);
        assert_ne!(TenantSource::Subdomain, TenantSource::Header);
    }
}
