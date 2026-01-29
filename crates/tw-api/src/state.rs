//! Application state shared across handlers.

use std::sync::Arc;
use tw_core::db::DbPool;
use tw_core::EventBus;

/// Shared application state.
#[derive(Clone)]
pub struct AppState {
    /// Database connection pool.
    pub db: Arc<DbPool>,
    /// Event bus for real-time updates.
    pub event_bus: Arc<EventBus>,
    /// Webhook secrets for signature validation.
    pub webhook_secrets: Arc<WebhookSecrets>,
}

impl AppState {
    /// Creates a new application state.
    pub fn new(db: DbPool, event_bus: EventBus) -> Self {
        Self {
            db: Arc::new(db),
            event_bus: Arc::new(event_bus),
            webhook_secrets: Arc::new(WebhookSecrets::default()),
        }
    }

    /// Creates a new application state with webhook secrets.
    pub fn with_webhook_secrets(mut self, secrets: WebhookSecrets) -> Self {
        self.webhook_secrets = Arc::new(secrets);
        self
    }
}

/// Webhook secrets for different sources.
#[derive(Debug, Clone, Default)]
pub struct WebhookSecrets {
    /// Default secret for generic webhooks.
    pub default: Option<String>,
    /// Source-specific secrets (source_name -> secret).
    pub sources: std::collections::HashMap<String, String>,
}

impl WebhookSecrets {
    /// Gets the secret for a given source.
    pub fn get(&self, source: &str) -> Option<&String> {
        self.sources.get(source).or(self.default.as_ref())
    }
}
