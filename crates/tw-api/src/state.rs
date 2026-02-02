//! Application state shared across handlers.

use metrics_exporter_prometheus::PrometheusHandle;
use std::sync::Arc;
use tracing::info;
use tw_core::db::DbPool;
use tw_core::{create_encryptor, CredentialEncryptor, EventBus};
use tw_policy::{KillSwitch, PolicyEngine};

/// Shared application state.
#[derive(Clone)]
pub struct AppState {
    /// Database connection pool.
    pub db: Arc<DbPool>,
    /// Event bus for real-time updates.
    pub event_bus: Arc<EventBus>,
    /// Webhook secrets for signature validation.
    pub webhook_secrets: Arc<WebhookSecrets>,
    /// Policy engine for evaluating actions against rules and guardrails.
    pub policy_engine: Arc<PolicyEngine>,
    /// Prometheus metrics handle for rendering metrics.
    pub prometheus_handle: Option<Arc<PrometheusHandle>>,
    /// Emergency kill switch for halting all automation.
    pub kill_switch: Arc<KillSwitch>,
    /// Credential encryptor for securing sensitive data at rest.
    pub encryptor: Arc<dyn CredentialEncryptor>,
}

impl AppState {
    /// Creates a new application state.
    pub fn new(db: DbPool, event_bus: EventBus) -> Self {
        let policy_engine = PolicyEngine::default();
        info!(
            rules_count = policy_engine.rules().len(),
            "Policy engine initialized with default rules"
        );

        Self {
            db: Arc::new(db),
            event_bus: Arc::new(event_bus),
            webhook_secrets: Arc::new(WebhookSecrets::default()),
            policy_engine: Arc::new(policy_engine),
            prometheus_handle: None,
            kill_switch: Arc::new(KillSwitch::new()),
            encryptor: create_encryptor(),
        }
    }

    /// Creates a new application state with webhook secrets.
    pub fn with_webhook_secrets(mut self, secrets: WebhookSecrets) -> Self {
        self.webhook_secrets = Arc::new(secrets);
        self
    }

    /// Creates a new application state with Prometheus handle.
    pub fn with_prometheus_handle(mut self, handle: PrometheusHandle) -> Self {
        self.prometheus_handle = Some(Arc::new(handle));
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
