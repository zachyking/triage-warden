//! # tw-core
//!
//! Core orchestrator and data models for Triage Warden.
//!
//! This crate provides the central orchestration loop, incident data models,
//! workflow state machine, and event bus for the Triage Warden system.

pub mod auth;
pub mod cache;
pub mod calibration;
pub mod connector;
pub mod crypto;
pub mod enrichment;
pub mod events;
pub mod features;
pub mod feedback;
pub mod incident;
pub mod knowledge;
pub mod leadership;
pub mod messaging;
pub mod notification;
pub mod orchestrator;
pub mod playbook;
pub mod policy;
pub mod tenant;
pub mod training;
pub mod validation;
pub mod vector;
pub mod workflow;

#[cfg(feature = "database")]
pub mod db;

pub use connector::{ConnectorConfig, ConnectorStatus, ConnectorType};
pub use events::{
    EventBus, EventBusBuilder, EventBusError, EventBusMetrics, EventBusMetricsSnapshot,
    EventEnvelope, TriageEvent, EVENT_SCHEMA_VERSION, TRIAGE_EVENTS_TOPIC,
};
pub use feedback::{
    AnalystFeedback, CalibrationQuality, CalibrationStats, ConfidenceBucketStats, FeedbackStats,
    FeedbackStatsByDimension, FeedbackType,
};
pub use incident::{
    Alert, AlertSource, AuditEntry, Enrichment, Incident, IncidentStatus, ProposedAction, Severity,
    TriageAnalysis, TriageVerdict,
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

// Vector store exports
pub use vector::{
    CollectionConfig, CollectionInfo, DistanceMetric, DynVectorStore, MockVectorStore,
    SearchFilter, SearchResult, VectorMetadata, VectorRecord, VectorStore, VectorStoreError,
    VectorStoreResult,
};

// Embedding pipeline exports
pub use vector::{
    CollectionStats, Embedder, EmbeddingConfig, EmbeddingError, EmbeddingResult,
    IncidentEmbeddingService, IncidentMetadata, IncidentTextSerializer, IndexStats, MockEmbedder,
    SimilarIncident, DEFAULT_EMBEDDING_DIMENSION, INCIDENTS_COLLECTION, MAX_TEXT_LENGTH,
};

// Indexer exports
pub use vector::{
    BatchIndexStats, BatchIndexer, IncidentIndexer, IncidentRepoForIndexer, IndexerConfig,
    IndexerHandle, IndexerStats,
};

// Training data exports
pub use training::{
    DateRange, ExpectedOutput, ExportConfig, ExportError, ExportFormat, ExportOutput, ExportResult,
    ExportStats, TrainingDataExporter, TrainingExample, TrainingMetadata,
};

// Calibration exports
pub use calibration::{
    CalibrationCurve, CalibrationCurveBuilder, CalibrationDataPoint, CalibrationError,
    CalibrationMetrics, CalibrationModel, CalibrationModelMetadata, CalibrationResult,
    CalibrationService, CalibrationServiceConfig, CalibrationType, CalibratorType,
    ConfidenceBucket, ConfidenceCalibrator, HistogramBinningCalibrator, IsotonicCalibrator,
    ReliabilityDiagramPoint, StratificationKey, GLOBAL_STRATIFICATION_KEY,
};

// Knowledge base exports
pub use knowledge::{
    CreateKnowledgeDocument, DocumentExtractor, DocumentFormat, DocumentMetadata,
    ExtractedDocument, ExtractionConfig, ExtractionError, ExtractionResult,
    KnowledgeCollectionStats, KnowledgeDocument, KnowledgeEmbeddingConfig,
    KnowledgeEmbeddingService, KnowledgeFilter, KnowledgeIndexStats, KnowledgeSearchResult,
    KnowledgeStats, KnowledgeType, UpdateKnowledgeDocument, KNOWLEDGE_COLLECTION,
    MAX_KNOWLEDGE_TEXT_LENGTH,
};

#[cfg(feature = "vector-store")]
pub use vector::{QdrantConfig, QdrantVectorStore};
