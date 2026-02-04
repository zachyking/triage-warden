//! Application state shared across handlers.

use metrics_exporter_prometheus::PrometheusHandle;
use std::sync::Arc;
use tracing::info;
use tw_core::db::DbPool;
use tw_core::{create_encryptor_or_panic, CredentialEncryptor, EventBus};
use tw_core::{DynCache, FeatureFlags, LeaderElector, MessageQueue};
use tw_policy::{KillSwitch, PolicyEngine};

use crate::rate_limit::{ApiRateLimiter, LoginRateLimiter, WebhookRateLimiter};

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
    /// Login rate limiter for protecting against brute force attacks.
    pub login_rate_limiter: LoginRateLimiter,
    /// API rate limiter for protecting against excessive API usage.
    pub api_rate_limiter: ApiRateLimiter,
    /// Webhook rate limiter for protecting against alert flooding.
    pub webhook_rate_limiter: WebhookRateLimiter,
    /// Message queue for distributed processing (optional, for horizontal scaling).
    pub message_queue: Option<Arc<dyn MessageQueue>>,
    /// Cache for enrichment results and frequently accessed data (optional).
    pub cache: Option<Arc<dyn DynCache>>,
    /// Leader elector for coordinating singleton tasks across instances (optional).
    pub leader_elector: Option<Arc<dyn LeaderElector>>,
    /// Feature flags for controlling feature availability.
    pub feature_flags: Arc<FeatureFlags>,
}

impl AppState {
    /// Creates a new application state with minimal configuration.
    ///
    /// For more control over initialization, use [`AppStateBuilder`] instead.
    pub fn new(db: DbPool, event_bus: EventBus, feature_flags: FeatureFlags) -> Self {
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
            encryptor: create_encryptor_or_panic(),
            login_rate_limiter: LoginRateLimiter::default(),
            api_rate_limiter: ApiRateLimiter::default(),
            webhook_rate_limiter: WebhookRateLimiter::default(),
            message_queue: None,
            cache: None,
            leader_elector: None,
            feature_flags: Arc::new(feature_flags),
        }
    }

    /// Creates a new builder for constructing AppState with fine-grained control.
    pub fn builder(
        db: DbPool,
        event_bus: EventBus,
        feature_flags: FeatureFlags,
    ) -> AppStateBuilder {
        AppStateBuilder::new(db, event_bus, feature_flags)
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

    /// Creates a new application state with a message queue.
    pub fn with_message_queue(mut self, queue: Arc<dyn MessageQueue>) -> Self {
        self.message_queue = Some(queue);
        self
    }

    /// Creates a new application state with a cache.
    pub fn with_cache(mut self, cache: Arc<dyn DynCache>) -> Self {
        self.cache = Some(cache);
        self
    }

    /// Creates a new application state with a leader elector.
    pub fn with_leader_elector(mut self, elector: Arc<dyn LeaderElector>) -> Self {
        self.leader_elector = Some(elector);
        self
    }

    /// Returns whether distributed features are available.
    ///
    /// Distributed features require message_queue, cache, and leader_elector
    /// to all be configured.
    pub fn has_distributed_features(&self) -> bool {
        self.message_queue.is_some() && self.cache.is_some() && self.leader_elector.is_some()
    }

    /// Returns whether the message queue is enabled.
    pub fn has_message_queue(&self) -> bool {
        self.message_queue.is_some()
    }

    /// Returns whether the cache is enabled.
    pub fn has_cache(&self) -> bool {
        self.cache.is_some()
    }

    /// Returns whether the leader elector is enabled.
    pub fn has_leader_elector(&self) -> bool {
        self.leader_elector.is_some()
    }
}

/// Builder for constructing [`AppState`] with fine-grained control.
///
/// Use this builder when you need to configure optional distributed components
/// like message queue, cache, and leader elector.
///
/// # Example
///
/// ```ignore
/// use tw_api::state::AppStateBuilder;
/// use tw_core::{MockMessageQueue, MockCache, MockLeaderElector};
///
/// let state = AppStateBuilder::new(db, event_bus, feature_flags)
///     .with_message_queue(Arc::new(MockMessageQueue::new()))
///     .with_cache(Arc::new(MockCache::new()))
///     .with_prometheus_handle(prometheus_handle)
///     .build();
/// ```
pub struct AppStateBuilder {
    db: DbPool,
    event_bus: EventBus,
    feature_flags: FeatureFlags,
    webhook_secrets: WebhookSecrets,
    policy_engine: Option<PolicyEngine>,
    prometheus_handle: Option<PrometheusHandle>,
    kill_switch: Option<KillSwitch>,
    encryptor: Option<Arc<dyn CredentialEncryptor>>,
    login_rate_limiter: Option<LoginRateLimiter>,
    api_rate_limiter: Option<ApiRateLimiter>,
    webhook_rate_limiter: Option<WebhookRateLimiter>,
    message_queue: Option<Arc<dyn MessageQueue>>,
    cache: Option<Arc<dyn DynCache>>,
    leader_elector: Option<Arc<dyn LeaderElector>>,
}

impl AppStateBuilder {
    /// Creates a new builder with required components.
    pub fn new(db: DbPool, event_bus: EventBus, feature_flags: FeatureFlags) -> Self {
        Self {
            db,
            event_bus,
            feature_flags,
            webhook_secrets: WebhookSecrets::default(),
            policy_engine: None,
            prometheus_handle: None,
            kill_switch: None,
            encryptor: None,
            login_rate_limiter: None,
            api_rate_limiter: None,
            webhook_rate_limiter: None,
            message_queue: None,
            cache: None,
            leader_elector: None,
        }
    }

    /// Sets the webhook secrets.
    pub fn with_webhook_secrets(mut self, secrets: WebhookSecrets) -> Self {
        self.webhook_secrets = secrets;
        self
    }

    /// Sets the policy engine.
    pub fn with_policy_engine(mut self, engine: PolicyEngine) -> Self {
        self.policy_engine = Some(engine);
        self
    }

    /// Sets the Prometheus metrics handle.
    pub fn with_prometheus_handle(mut self, handle: PrometheusHandle) -> Self {
        self.prometheus_handle = Some(handle);
        self
    }

    /// Sets the kill switch.
    pub fn with_kill_switch(mut self, kill_switch: KillSwitch) -> Self {
        self.kill_switch = Some(kill_switch);
        self
    }

    /// Sets the credential encryptor.
    pub fn with_encryptor(mut self, encryptor: Arc<dyn CredentialEncryptor>) -> Self {
        self.encryptor = Some(encryptor);
        self
    }

    /// Sets the login rate limiter.
    pub fn with_login_rate_limiter(mut self, limiter: LoginRateLimiter) -> Self {
        self.login_rate_limiter = Some(limiter);
        self
    }

    /// Sets the API rate limiter.
    pub fn with_api_rate_limiter(mut self, limiter: ApiRateLimiter) -> Self {
        self.api_rate_limiter = Some(limiter);
        self
    }

    /// Sets the webhook rate limiter.
    pub fn with_webhook_rate_limiter(mut self, limiter: WebhookRateLimiter) -> Self {
        self.webhook_rate_limiter = Some(limiter);
        self
    }

    /// Sets the message queue for distributed processing.
    pub fn with_message_queue(mut self, queue: Arc<dyn MessageQueue>) -> Self {
        self.message_queue = Some(queue);
        self
    }

    /// Sets the cache for enrichment results.
    pub fn with_cache(mut self, cache: Arc<dyn DynCache>) -> Self {
        self.cache = Some(cache);
        self
    }

    /// Sets the leader elector for coordinating singleton tasks.
    pub fn with_leader_elector(mut self, elector: Arc<dyn LeaderElector>) -> Self {
        self.leader_elector = Some(elector);
        self
    }

    /// Builds the AppState with all configured components.
    ///
    /// Components not explicitly set will use their defaults:
    /// - `policy_engine`: Default policy engine with built-in rules
    /// - `kill_switch`: New inactive kill switch
    /// - `encryptor`: Environment-based encryptor (panics if encryption key not set in production)
    /// - Rate limiters: Default configuration
    /// - Distributed components (message_queue, cache, leader_elector): None (disabled)
    pub fn build(self) -> AppState {
        let policy_engine = self.policy_engine.unwrap_or_default();
        info!(
            rules_count = policy_engine.rules().len(),
            "Policy engine initialized"
        );

        // Log which distributed components are enabled
        let mq_enabled = self.message_queue.is_some();
        let cache_enabled = self.cache.is_some();
        let leader_enabled = self.leader_elector.is_some();

        info!(
            message_queue = mq_enabled,
            cache = cache_enabled,
            leader_elector = leader_enabled,
            "Distributed components configuration"
        );

        if mq_enabled && cache_enabled && leader_enabled {
            info!("All distributed features enabled - horizontal scaling ready");
        } else if !mq_enabled && !cache_enabled && !leader_enabled {
            info!("Running in standalone mode (no distributed features)");
        } else {
            info!("Running with partial distributed features");
        }

        AppState {
            db: Arc::new(self.db),
            event_bus: Arc::new(self.event_bus),
            webhook_secrets: Arc::new(self.webhook_secrets),
            policy_engine: Arc::new(policy_engine),
            prometheus_handle: self.prometheus_handle.map(Arc::new),
            kill_switch: Arc::new(self.kill_switch.unwrap_or_default()),
            encryptor: self.encryptor.unwrap_or_else(create_encryptor_or_panic),
            login_rate_limiter: self.login_rate_limiter.unwrap_or_default(),
            api_rate_limiter: self.api_rate_limiter.unwrap_or_default(),
            webhook_rate_limiter: self.webhook_rate_limiter.unwrap_or_default(),
            message_queue: self.message_queue,
            cache: self.cache,
            leader_elector: self.leader_elector,
            feature_flags: Arc::new(self.feature_flags),
        }
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
