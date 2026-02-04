//! # tw-core
//!
//! Core orchestrator and data models for Triage Warden.
//!
//! This crate provides the central orchestration loop, incident data models,
//! workflow state machine, and event bus for the Triage Warden system.

pub mod auth;
pub mod cache;
pub mod connector;
pub mod crypto;
pub mod enrichment;
pub mod events;
pub mod features;
pub mod incident;
pub mod leadership;
pub mod messaging;
pub mod notification;
pub mod orchestrator;
pub mod playbook;
pub mod policy;
pub mod tenant;
pub mod validation;
pub mod workflow;

#[cfg(feature = "database")]
pub mod db;

pub use connector::{ConnectorConfig, ConnectorStatus, ConnectorType};
pub use events::{
    EventBus, EventBusBuilder, EventBusError, EventBusMetrics, EventBusMetricsSnapshot,
    EventEnvelope, TriageEvent, EVENT_SCHEMA_VERSION, TRIAGE_EVENTS_TOPIC,
};
pub use incident::{
    Alert, AlertSource, AuditEntry, Enrichment, Incident, IncidentStatus, ProposedAction, Severity,
    TriageAnalysis,
};
pub use notification::{
    ChannelType, NotificationChannel, NotificationChannelUpdate, NOTIFICATION_EVENTS,
};
pub use orchestrator::Orchestrator;
pub use playbook::{Playbook, PlaybookStage, PlaybookStep};
pub use policy::{ApprovalLevel, Policy, PolicyAction};
pub use workflow::{
    ManualApprovalRequest, ManualApprovalStatus, WorkflowEngine, WorkflowState, WorkflowTransition,
    DEFAULT_APPROVAL_TIMEOUT_HOURS,
};

// Auth exports
pub use auth::password::{
    hash_password, validate_password_strength, verify_password, PasswordError,
};
pub use auth::{
    is_destructive_action, ApiKey, AuthorizationContext, AuthorizationError, Permission, Role,
    SessionData, User, UserFilter, UserUpdate, DESTRUCTIVE_ACTIONS,
};

// Crypto exports
pub use crypto::{
    create_encryptor, create_encryptor_or_panic, generate_encryption_key,
    is_production_environment, Aes256GcmEncryptor, CredentialEncryptor, CryptoError,
    PlaintextEncryptor, SecureString,
};

// Validation exports
pub use validation::{
    validate_email, validate_email_with_options, EmailValidationError, EmailValidationOptions,
    HostnameValidationError, ValidatedEmail, ValidatedHostname,
};

// Cache exports
pub use cache::{Cache, CacheEntry, CacheError, CacheResult, CacheStats, DynCache, MockCache};

// Leadership exports
pub use leadership::{
    default_instance_id, LeaderElectionError, LeaderElector, LeaderElectorConfig, LeaderInfo,
    LeaderLease, MockLeaderElector,
};

// Messaging exports
pub use messaging::{
    Message, MessageId, MessageQueue, MessageQueueError, MessageQueueResult, MockMessageQueue,
    QueueHealth, SubscribeOptions, Subscription,
};

// Tenant exports
pub use tenant::{Tenant, TenantContext, TenantError, TenantSettings, TenantStatus};

// Feature flag exports
pub use features::{
    FeatureFlag, FeatureFlagError, FeatureFlagStore, FeatureFlags, InMemoryFeatureFlagStore,
};

// Enrichment exports
pub use enrichment::{
    CachedEnrichment, CachedEnrichmentStats, EnrichmentCacheOptions, EnrichmentConfig,
    EnrichmentError, EnrichmentResult, ThreatIntelRequest, ENRICHMENT_CACHE_FLAG,
};
