//! Incident embedding pipeline for RAG (Retrieval Augmented Generation).
//!
//! This module provides functionality to embed security incidents as vectors
//! for semantic similarity search. It supports:
//!
//! - Converting incidents to text representations suitable for embedding
//! - Batch indexing of existing incidents (startup/migration)
//! - Real-time indexing when incidents are created/updated
//! - Incremental re-indexing when analysis results are updated
//! - Similarity search for finding related incidents
//!
//! # Architecture
//!
//! The embedding pipeline is designed to be flexible with regards to the embedding
//! model used. The [`Embedder`] trait abstracts the embedding model, allowing
//! different implementations (OpenAI, local models, etc.).
//!
//! ```text
//! ┌─────────────┐    ┌────────────┐    ┌─────────────────┐    ┌─────────────┐
//! │  Incident   │───►│  Text      │───►│  Embedder       │───►│  Vector     │
//! │  Data       │    │  Serializer│    │  (OpenAI, etc.) │    │  Store      │
//! └─────────────┘    └────────────┘    └─────────────────┘    └─────────────┘
//! ```
//!
//! # Example
//!
//! ```ignore
//! use tw_core::vector::embeddings::{IncidentEmbeddingService, EmbeddingConfig};
//! use tw_core::vector::MockVectorStore;
//!
//! // Create with mock embedder for testing
//! let vector_store = Arc::new(MockVectorStore::new());
//! let embedder = Arc::new(MockEmbedder::new(384));
//! let config = EmbeddingConfig::default();
//!
//! let service = IncidentEmbeddingService::new(vector_store, embedder, config);
//!
//! // Index an incident
//! service.index_incident(&incident).await?;
//!
//! // Find similar incidents
//! let similar = service.find_similar(&incident, 5).await?;
//! ```

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, info, instrument, warn};
use uuid::Uuid;

use crate::incident::{Enrichment, EnrichmentType, Incident, TriageAnalysis};

use super::{
    CollectionConfig, SearchFilter, SearchResult, VectorMetadata, VectorRecord, VectorStore,
    VectorStoreError,
};

/// Collection name for incident embeddings.
pub const INCIDENTS_COLLECTION: &str = "incidents";

/// Default embedding dimension (OpenAI text-embedding-3-small).
pub const DEFAULT_EMBEDDING_DIMENSION: usize = 1536;

/// Maximum text length for embedding (characters).
/// Most embedding models have a token limit; we truncate to stay within bounds.
pub const MAX_TEXT_LENGTH: usize = 8000;

/// Error type for embedding operations.
#[derive(Debug, Error)]
pub enum EmbeddingError {
    /// Error from the embedding model.
    #[error("Embedding model error: {0}")]
    Model(String),

    /// Error from the vector store.
    #[error("Vector store error: {0}")]
    VectorStore(#[from] VectorStoreError),

    /// Error serializing incident data.
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Configuration error.
    #[error("Configuration error: {0}")]
    Configuration(String),

    /// Rate limit exceeded.
    #[error("Rate limit exceeded: {0}")]
    RateLimit(String),
}

/// Result type for embedding operations.
pub type EmbeddingResult<T> = Result<T, EmbeddingError>;

/// Configuration for the embedding service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddingConfig {
    /// Vector dimension (must match the embedding model).
    pub dimension: usize,

    /// Collection name for incidents.
    pub collection_name: String,

    /// Whether to include enrichment data in the embedding text.
    #[serde(default = "default_true")]
    pub include_enrichments: bool,

    /// Whether to include analysis results in the embedding text.
    #[serde(default = "default_true")]
    pub include_analysis: bool,

    /// Whether to store vectors on disk (for large collections).
    #[serde(default)]
    pub on_disk: bool,

    /// Batch size for bulk indexing operations.
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,

    /// Maximum concurrent embedding requests.
    #[serde(default = "default_concurrency")]
    pub max_concurrency: usize,
}

fn default_true() -> bool {
    true
}

fn default_batch_size() -> usize {
    100
}

fn default_concurrency() -> usize {
    10
}

impl Default for EmbeddingConfig {
    fn default() -> Self {
        Self {
            dimension: DEFAULT_EMBEDDING_DIMENSION,
            collection_name: INCIDENTS_COLLECTION.to_string(),
            include_enrichments: true,
            include_analysis: true,
            on_disk: false,
            batch_size: default_batch_size(),
            max_concurrency: default_concurrency(),
        }
    }
}

impl EmbeddingConfig {
    /// Create a new config with the specified dimension.
    pub fn new(dimension: usize) -> Self {
        Self {
            dimension,
            ..Default::default()
        }
    }

    /// Set the collection name.
    pub fn with_collection_name(mut self, name: impl Into<String>) -> Self {
        self.collection_name = name.into();
        self
    }

    /// Enable on-disk storage.
    pub fn with_on_disk(mut self, on_disk: bool) -> Self {
        self.on_disk = on_disk;
        self
    }

    /// Set batch size for bulk operations.
    pub fn with_batch_size(mut self, batch_size: usize) -> Self {
        self.batch_size = batch_size;
        self
    }
}

/// Trait for embedding text into vectors.
///
/// Implementations should be thread-safe and handle rate limiting internally.
#[async_trait]
pub trait Embedder: Send + Sync {
    /// Embed a single text string.
    async fn embed(&self, text: &str) -> EmbeddingResult<Vec<f32>>;

    /// Embed multiple texts in a batch (more efficient for bulk operations).
    ///
    /// Default implementation calls `embed` sequentially.
    async fn embed_batch(&self, texts: &[&str]) -> EmbeddingResult<Vec<Vec<f32>>> {
        let mut results = Vec::with_capacity(texts.len());
        for text in texts {
            results.push(self.embed(text).await?);
        }
        Ok(results)
    }

    /// Get the embedding dimension.
    fn dimension(&self) -> usize;

    /// Get the model identifier.
    fn model_id(&self) -> &str;
}

/// A mock embedder for testing purposes.
///
/// Generates deterministic embeddings based on text content.
pub struct MockEmbedder {
    dimension: usize,
    model_id: String,
}

impl MockEmbedder {
    /// Create a new mock embedder with the specified dimension.
    pub fn new(dimension: usize) -> Self {
        Self {
            dimension,
            model_id: "mock-embedder".to_string(),
        }
    }

    /// Generate a deterministic embedding from text.
    fn generate_embedding(&self, text: &str) -> Vec<f32> {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        text.hash(&mut hasher);
        let hash = hasher.finish();

        // Generate deterministic values based on hash
        let mut embedding = Vec::with_capacity(self.dimension);
        let mut seed = hash;
        for _ in 0..self.dimension {
            // Simple LCG for deterministic pseudo-random values
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            // Normalize to [-1, 1] range
            let value = ((seed as f64) / (u64::MAX as f64) * 2.0 - 1.0) as f32;
            embedding.push(value);
        }

        // Normalize the vector
        let magnitude: f32 = embedding.iter().map(|x| x * x).sum::<f32>().sqrt();
        if magnitude > 0.0 {
            for v in &mut embedding {
                *v /= magnitude;
            }
        }

        embedding
    }
}

#[async_trait]
impl Embedder for MockEmbedder {
    async fn embed(&self, text: &str) -> EmbeddingResult<Vec<f32>> {
        Ok(self.generate_embedding(text))
    }

    async fn embed_batch(&self, texts: &[&str]) -> EmbeddingResult<Vec<Vec<f32>>> {
        Ok(texts.iter().map(|t| self.generate_embedding(t)).collect())
    }

    fn dimension(&self) -> usize {
        self.dimension
    }

    fn model_id(&self) -> &str {
        &self.model_id
    }
}

/// Metadata fields stored with incident embeddings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentMetadata {
    /// Document type (always "incident" for incidents).
    pub doc_type: String,
    /// Tenant ID for multi-tenancy.
    pub tenant_id: Uuid,
    /// Incident severity level.
    pub severity: String,
    /// Incident status.
    pub status: String,
    /// Alert source type.
    pub source_type: String,
    /// Verdict from analysis (if available).
    pub verdict: Option<String>,
    /// Confidence score from analysis (if available).
    pub confidence: Option<f64>,
    /// MITRE ATT&CK technique IDs.
    pub mitre_techniques: Vec<String>,
    /// Tags for categorization.
    pub tags: Vec<String>,
    /// When the incident was created.
    pub created_at: DateTime<Utc>,
    /// When the incident was last updated.
    pub updated_at: DateTime<Utc>,
    /// When the embedding was created/updated.
    pub indexed_at: DateTime<Utc>,
}

impl IncidentMetadata {
    /// Create metadata from an incident.
    pub fn from_incident(incident: &Incident) -> Self {
        let (verdict, confidence, mitre_techniques) = if let Some(ref analysis) = incident.analysis
        {
            (
                Some(format!("{:?}", analysis.verdict)),
                Some(analysis.confidence),
                analysis
                    .mitre_techniques
                    .iter()
                    .map(|t| t.id.clone())
                    .collect(),
            )
        } else {
            (None, None, vec![])
        };

        Self {
            doc_type: "incident".to_string(),
            tenant_id: incident.tenant_id,
            severity: format!("{:?}", incident.severity).to_lowercase(),
            status: incident.status.as_db_str().to_string(),
            source_type: Self::source_type(&incident.source),
            verdict,
            confidence,
            mitre_techniques,
            tags: incident.tags.clone(),
            created_at: incident.created_at,
            updated_at: incident.updated_at,
            indexed_at: Utc::now(),
        }
    }

    /// Extract source type from alert source.
    fn source_type(source: &crate::incident::AlertSource) -> String {
        use crate::incident::AlertSource;
        match source {
            AlertSource::Siem(_) => "siem".to_string(),
            AlertSource::Edr(_) => "edr".to_string(),
            AlertSource::EmailSecurity(_) => "email_security".to_string(),
            AlertSource::IdentityProvider(_) => "identity_provider".to_string(),
            AlertSource::CloudSecurity(_) => "cloud_security".to_string(),
            AlertSource::UserReported => "user_reported".to_string(),
            AlertSource::Custom(_) => "custom".to_string(),
        }
    }

    /// Convert to VectorMetadata for storage.
    pub fn to_vector_metadata(&self) -> VectorMetadata {
        use serde_json::json;

        VectorMetadata::new()
            .with_field("doc_type", json!(self.doc_type))
            .with_field("tenant_id", json!(self.tenant_id.to_string()))
            .with_field("severity", json!(self.severity))
            .with_field("status", json!(self.status))
            .with_field("source_type", json!(self.source_type))
            .with_field("verdict", json!(self.verdict))
            .with_field("confidence", json!(self.confidence))
            .with_field("mitre_techniques", json!(self.mitre_techniques))
            .with_field("tags", json!(self.tags))
            .with_field("created_at", json!(self.created_at.to_rfc3339()))
            .with_field("updated_at", json!(self.updated_at.to_rfc3339()))
            .with_field("indexed_at", json!(self.indexed_at.to_rfc3339()))
    }
}

/// Serializes an incident to text format suitable for embedding.
///
/// The text representation includes:
/// - Alert source and type
/// - Severity and status
/// - Alert data summary
/// - Enrichment summaries (if configured)
/// - Analysis results (if configured and available)
/// - Tags and metadata
pub struct IncidentTextSerializer {
    /// Whether to include enrichment data.
    include_enrichments: bool,
    /// Whether to include analysis results.
    include_analysis: bool,
}

impl IncidentTextSerializer {
    /// Create a new serializer with default settings.
    pub fn new() -> Self {
        Self {
            include_enrichments: true,
            include_analysis: true,
        }
    }

    /// Create from configuration.
    pub fn from_config(config: &EmbeddingConfig) -> Self {
        Self {
            include_enrichments: config.include_enrichments,
            include_analysis: config.include_analysis,
        }
    }

    /// Serialize an incident to text.
    pub fn serialize(&self, incident: &Incident) -> String {
        let mut parts = Vec::new();

        // Header with source and severity
        parts.push(format!(
            "Security Incident from {} - Severity: {} - Status: {}",
            incident.source, incident.severity, incident.status
        ));

        // Alert data summary
        if let Some(title) = incident.alert_data.get("title").and_then(|v| v.as_str()) {
            parts.push(format!("Title: {}", title));
        }
        if let Some(desc) = incident
            .alert_data
            .get("description")
            .and_then(|v| v.as_str())
        {
            parts.push(format!("Description: {}", desc));
        }
        if let Some(alert_type) = incident
            .alert_data
            .get("alert_type")
            .and_then(|v| v.as_str())
        {
            parts.push(format!("Alert Type: {}", alert_type));
        }

        // Include key fields from alert_data
        self.serialize_alert_data(&incident.alert_data, &mut parts);

        // Enrichments
        if self.include_enrichments && !incident.enrichments.is_empty() {
            parts.push("--- Enrichments ---".to_string());
            for enrichment in &incident.enrichments {
                self.serialize_enrichment(enrichment, &mut parts);
            }
        }

        // Analysis results
        if self.include_analysis {
            if let Some(ref analysis) = incident.analysis {
                parts.push("--- Analysis Results ---".to_string());
                self.serialize_analysis(analysis, &mut parts);
            }
        }

        // Tags
        if !incident.tags.is_empty() {
            parts.push(format!("Tags: {}", incident.tags.join(", ")));
        }

        // Join and truncate
        let text = parts.join("\n");
        if text.len() > MAX_TEXT_LENGTH {
            text[..MAX_TEXT_LENGTH].to_string()
        } else {
            text
        }
    }

    /// Serialize alert data fields.
    fn serialize_alert_data(&self, data: &serde_json::Value, parts: &mut Vec<String>) {
        if let Some(obj) = data.as_object() {
            // Extract common security-relevant fields
            let important_fields = [
                "src_ip",
                "dest_ip",
                "source_ip",
                "destination_ip",
                "hostname",
                "user",
                "username",
                "email",
                "sender",
                "recipient",
                "domain",
                "url",
                "hash",
                "md5",
                "sha256",
                "file_name",
                "file_path",
                "process",
                "command_line",
                "event_type",
                "action",
                "category",
            ];

            for field in important_fields {
                if let Some(value) = obj.get(field) {
                    let value_str = match value {
                        serde_json::Value::String(s) => s.clone(),
                        serde_json::Value::Array(arr) => arr
                            .iter()
                            .filter_map(|v| v.as_str())
                            .collect::<Vec<_>>()
                            .join(", "),
                        _ => continue,
                    };
                    if !value_str.is_empty() {
                        parts.push(format!("{}: {}", field, value_str));
                    }
                }
            }
        }
    }

    /// Serialize enrichment data.
    fn serialize_enrichment(&self, enrichment: &Enrichment, parts: &mut Vec<String>) {
        let type_name = match &enrichment.enrichment_type {
            EnrichmentType::ThreatIntel => "Threat Intelligence",
            EnrichmentType::HostInfo => "Host Information",
            EnrichmentType::UserInfo => "User Information",
            EnrichmentType::SiemSearch => "SIEM Search Results",
            EnrichmentType::EmailAnalysis => "Email Analysis",
            EnrichmentType::GeoLocation => "Geolocation",
            EnrichmentType::Whois => "WHOIS",
            EnrichmentType::MitreMapping => "MITRE ATT&CK Mapping",
            EnrichmentType::HistoricalCorrelation => "Historical Correlation",
            EnrichmentType::Custom(name) => name.as_str(),
        };

        parts.push(format!("[{}] Source: {}", type_name, enrichment.source));

        // Extract key findings from enrichment data
        if let Some(obj) = enrichment.data.as_object() {
            // Common enrichment fields
            let fields_to_include = [
                "reputation",
                "score",
                "malicious",
                "suspicious",
                "threat_type",
                "category",
                "country",
                "city",
                "asn",
                "registrar",
                "correlation_count",
                "similar_incidents",
            ];

            for field in fields_to_include {
                if let Some(value) = obj.get(field) {
                    parts.push(format!("  {}: {}", field, value));
                }
            }
        }
    }

    /// Serialize analysis results.
    fn serialize_analysis(&self, analysis: &TriageAnalysis, parts: &mut Vec<String>) {
        parts.push(format!(
            "Verdict: {:?} (Confidence: {:.0}%)",
            analysis.verdict,
            analysis.confidence * 100.0
        ));
        parts.push(format!("Risk Score: {}/100", analysis.risk_score));
        parts.push(format!("Summary: {}", analysis.summary));

        // MITRE techniques
        if !analysis.mitre_techniques.is_empty() {
            let techniques: Vec<String> = analysis
                .mitre_techniques
                .iter()
                .map(|t| format!("{} ({})", t.id, t.name))
                .collect();
            parts.push(format!("MITRE Techniques: {}", techniques.join(", ")));
        }

        // IoCs
        if !analysis.iocs.is_empty() {
            parts.push("Indicators of Compromise:".to_string());
            for ioc in &analysis.iocs {
                parts.push(format!("  {:?}: {}", ioc.ioc_type, ioc.value));
            }
        }

        // Recommendations
        if !analysis.recommendations.is_empty() {
            parts.push(format!(
                "Recommendations: {}",
                analysis.recommendations.join("; ")
            ));
        }

        // Evidence summary (if available)
        if !analysis.evidence.is_empty() {
            parts.push(format!(
                "Evidence items: {} pieces of supporting evidence",
                analysis.evidence.len()
            ));
        }
    }
}

impl Default for IncidentTextSerializer {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of a similarity search.
#[derive(Debug, Clone)]
pub struct SimilarIncident {
    /// The incident ID.
    pub incident_id: Uuid,
    /// Similarity score (0.0 to 1.0, higher is more similar).
    pub score: f32,
    /// Metadata from the stored embedding.
    pub metadata: IncidentMetadata,
}

/// Service for managing incident embeddings.
///
/// Handles embedding generation, storage, and retrieval for semantic search
/// over security incidents.
pub struct IncidentEmbeddingService<V: VectorStore, E: Embedder> {
    /// The vector store for persistence.
    vector_store: Arc<V>,
    /// The embedder for generating vectors.
    embedder: Arc<E>,
    /// Text serializer for incidents.
    serializer: IncidentTextSerializer,
    /// Configuration.
    config: EmbeddingConfig,
}

impl<V: VectorStore, E: Embedder> IncidentEmbeddingService<V, E> {
    /// Create a new embedding service.
    pub fn new(vector_store: Arc<V>, embedder: Arc<E>, config: EmbeddingConfig) -> Self {
        let serializer = IncidentTextSerializer::from_config(&config);
        Self {
            vector_store,
            embedder,
            serializer,
            config,
        }
    }

    /// Initialize the incidents collection if it doesn't exist.
    #[instrument(skip(self))]
    pub async fn initialize(&self) -> EmbeddingResult<()> {
        let exists = self
            .vector_store
            .collection_exists(&self.config.collection_name)
            .await?;

        if !exists {
            info!(
                collection = %self.config.collection_name,
                dimension = self.config.dimension,
                "Creating incidents collection"
            );

            let collection_config = CollectionConfig::new(self.config.dimension)
                .with_cosine()
                .with_on_disk(self.config.on_disk);

            self.vector_store
                .create_collection(&self.config.collection_name, collection_config)
                .await?;

            info!(
                collection = %self.config.collection_name,
                "Incidents collection created"
            );
        } else {
            debug!(
                collection = %self.config.collection_name,
                "Incidents collection already exists"
            );
        }

        Ok(())
    }

    /// Index a single incident.
    ///
    /// Creates or updates the embedding for the incident in the vector store.
    #[instrument(skip(self, incident), fields(incident_id = %incident.id))]
    pub async fn index_incident(&self, incident: &Incident) -> EmbeddingResult<()> {
        // Serialize incident to text
        let text = self.serializer.serialize(incident);

        // Generate embedding
        let embedding = self.embedder.embed(&text).await?;

        // Create metadata
        let metadata = IncidentMetadata::from_incident(incident);

        // Upsert to vector store
        self.vector_store
            .upsert(
                &self.config.collection_name,
                &incident.id.to_string(),
                &embedding,
                metadata.to_vector_metadata(),
            )
            .await?;

        debug!(
            incident_id = %incident.id,
            text_length = text.len(),
            "Indexed incident"
        );

        Ok(())
    }

    /// Index multiple incidents in a batch.
    ///
    /// More efficient than indexing one at a time for bulk operations.
    #[instrument(skip(self, incidents), fields(count = incidents.len()))]
    pub async fn index_incidents(&self, incidents: &[Incident]) -> EmbeddingResult<IndexStats> {
        if incidents.is_empty() {
            return Ok(IndexStats::default());
        }

        let mut stats = IndexStats::default();
        let total = incidents.len();

        // Process in batches
        for chunk in incidents.chunks(self.config.batch_size) {
            // Serialize all incidents in the chunk
            let texts: Vec<String> = chunk.iter().map(|i| self.serializer.serialize(i)).collect();
            let text_refs: Vec<&str> = texts.iter().map(|s| s.as_str()).collect();

            // Generate embeddings in batch
            match self.embedder.embed_batch(&text_refs).await {
                Ok(embeddings) => {
                    // Create records for batch upsert
                    let records: Vec<VectorRecord> = chunk
                        .iter()
                        .zip(embeddings.into_iter())
                        .map(|(incident, embedding)| {
                            let metadata = IncidentMetadata::from_incident(incident);
                            VectorRecord::new(
                                incident.id.to_string(),
                                embedding,
                                metadata.to_vector_metadata(),
                            )
                        })
                        .collect();

                    // Batch upsert
                    if let Err(e) = self
                        .vector_store
                        .upsert_batch(&self.config.collection_name, records)
                        .await
                    {
                        warn!(error = %e, "Failed to upsert batch");
                        stats.failed += chunk.len();
                    } else {
                        stats.indexed += chunk.len();
                    }
                }
                Err(e) => {
                    warn!(error = %e, "Failed to generate embeddings for batch");
                    stats.failed += chunk.len();
                }
            }

            debug!(
                indexed = stats.indexed,
                failed = stats.failed,
                total = total,
                "Batch progress"
            );
        }

        info!(
            indexed = stats.indexed,
            failed = stats.failed,
            total = total,
            "Batch indexing complete"
        );

        Ok(stats)
    }

    /// Delete an incident's embedding from the vector store.
    #[instrument(skip(self), fields(incident_id = %incident_id))]
    pub async fn delete_incident(&self, incident_id: Uuid) -> EmbeddingResult<()> {
        self.vector_store
            .delete(&self.config.collection_name, &incident_id.to_string())
            .await?;

        debug!(incident_id = %incident_id, "Deleted incident embedding");

        Ok(())
    }

    /// Find similar incidents using semantic search.
    ///
    /// Returns incidents most similar to the given incident, excluding the incident itself.
    #[instrument(skip(self, incident), fields(incident_id = %incident.id, top_k = top_k))]
    pub async fn find_similar(
        &self,
        incident: &Incident,
        top_k: usize,
    ) -> EmbeddingResult<Vec<SimilarIncident>> {
        // Generate embedding for the query incident
        let text = self.serializer.serialize(incident);
        let embedding = self.embedder.embed(&text).await?;

        self.find_similar_by_embedding(
            &embedding,
            top_k,
            Some(incident.id),
            Some(incident.tenant_id),
        )
        .await
    }

    /// Find similar incidents by embedding vector.
    ///
    /// Allows searching with a pre-computed embedding or from external sources.
    pub async fn find_similar_by_embedding(
        &self,
        embedding: &[f32],
        top_k: usize,
        exclude_id: Option<Uuid>,
        tenant_id: Option<Uuid>,
    ) -> EmbeddingResult<Vec<SimilarIncident>> {
        // Build filter
        let filter = tenant_id.map(|tid| SearchFilter::equals("tenant_id", tid.to_string()));

        // Search with extra results to account for filtering
        let extra = if exclude_id.is_some() { 1 } else { 0 };
        let results = self
            .vector_store
            .search(
                &self.config.collection_name,
                embedding,
                top_k + extra,
                filter,
            )
            .await?;

        // Convert results and filter out excluded ID
        let similar: Vec<SimilarIncident> = results
            .into_iter()
            .filter_map(|r| {
                let incident_id = Uuid::parse_str(&r.id).ok()?;

                // Skip excluded incident
                if let Some(exclude) = exclude_id {
                    if incident_id == exclude {
                        return None;
                    }
                }

                Some(SimilarIncident {
                    incident_id,
                    score: r.score,
                    metadata: self.metadata_from_search_result(&r),
                })
            })
            .take(top_k)
            .collect();

        debug!(
            found = similar.len(),
            top_k = top_k,
            "Found similar incidents"
        );

        Ok(similar)
    }

    /// Find similar incidents by text query.
    ///
    /// Useful for ad-hoc searches without a full incident object.
    #[instrument(skip(self), fields(query_length = query.len(), top_k = top_k))]
    pub async fn find_similar_by_text(
        &self,
        query: &str,
        top_k: usize,
        tenant_id: Option<Uuid>,
    ) -> EmbeddingResult<Vec<SimilarIncident>> {
        let embedding = self.embedder.embed(query).await?;
        self.find_similar_by_embedding(&embedding, top_k, None, tenant_id)
            .await
    }

    /// Get collection statistics.
    pub async fn get_stats(&self) -> EmbeddingResult<CollectionStats> {
        let info = self
            .vector_store
            .collection_info(&self.config.collection_name)
            .await?;

        Ok(CollectionStats {
            collection_name: info.name,
            vector_count: info.vectors_count,
            dimension: info.dimension,
        })
    }

    /// Extract metadata from a search result.
    fn metadata_from_search_result(&self, result: &SearchResult) -> IncidentMetadata {
        use serde_json::Value;

        let get_str = |key: &str| -> String {
            result
                .metadata
                .get(key)
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string()
        };

        let get_opt_str = |key: &str| -> Option<String> {
            result.metadata.get(key).and_then(|v| match v {
                Value::String(s) => Some(s.clone()),
                Value::Null => None,
                _ => None,
            })
        };

        let get_opt_f64 =
            |key: &str| -> Option<f64> { result.metadata.get(key).and_then(|v| v.as_f64()) };

        let get_vec_str = |key: &str| -> Vec<String> {
            result
                .metadata
                .get(key)
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default()
        };

        let parse_datetime = |key: &str| -> DateTime<Utc> {
            result
                .metadata
                .get(key)
                .and_then(|v| v.as_str())
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(Utc::now)
        };

        IncidentMetadata {
            doc_type: get_str("doc_type"),
            tenant_id: result
                .metadata
                .get("tenant_id")
                .and_then(|v| v.as_str())
                .and_then(|s| Uuid::parse_str(s).ok())
                .unwrap_or_default(),
            severity: get_str("severity"),
            status: get_str("status"),
            source_type: get_str("source_type"),
            verdict: get_opt_str("verdict"),
            confidence: get_opt_f64("confidence"),
            mitre_techniques: get_vec_str("mitre_techniques"),
            tags: get_vec_str("tags"),
            created_at: parse_datetime("created_at"),
            updated_at: parse_datetime("updated_at"),
            indexed_at: parse_datetime("indexed_at"),
        }
    }
}

/// Statistics from a batch indexing operation.
#[derive(Debug, Clone, Default)]
pub struct IndexStats {
    /// Number of incidents successfully indexed.
    pub indexed: usize,
    /// Number of incidents that failed to index.
    pub failed: usize,
}

/// Statistics about the incident collection.
#[derive(Debug, Clone)]
pub struct CollectionStats {
    /// Collection name.
    pub collection_name: String,
    /// Number of vectors in the collection.
    pub vector_count: u64,
    /// Vector dimension.
    pub dimension: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::incident::{
        Alert, AlertSource, IoC, IoCType, MitreTechnique, Severity, TriageAnalysis, TriageVerdict,
    };
    use crate::vector::MockVectorStore;

    fn create_test_incident() -> Incident {
        let alert = Alert {
            id: "alert-123".to_string(),
            source: AlertSource::EmailSecurity("M365".to_string()),
            alert_type: "phishing".to_string(),
            severity: Severity::High,
            title: "Suspected phishing email".to_string(),
            description: Some("User reported suspicious email with attachment".to_string()),
            data: serde_json::json!({
                "title": "Suspected phishing email",
                "description": "User reported suspicious email",
                "sender": "attacker@malicious.com",
                "recipient": "victim@company.com",
                "subject": "Urgent: Update your password",
                "hash": "d41d8cd98f00b204e9800998ecf8427e"
            }),
            timestamp: Utc::now(),
            tags: vec!["phishing".to_string(), "user-reported".to_string()],
        };

        let mut incident = Incident::from_alert(alert);
        incident.id = Uuid::new_v4();
        incident
    }

    fn create_incident_with_analysis() -> Incident {
        let mut incident = create_test_incident();

        incident.analysis = Some(TriageAnalysis {
            verdict: TriageVerdict::TruePositive,
            confidence: 0.95,
            calibrated_confidence: None,
            summary: "Confirmed phishing attempt targeting employee credentials".to_string(),
            reasoning: "Email contains known phishing indicators".to_string(),
            mitre_techniques: vec![MitreTechnique {
                id: "T1566.001".to_string(),
                name: "Spearphishing Attachment".to_string(),
                tactic: "Initial Access".to_string(),
                confidence: 0.9,
            }],
            iocs: vec![IoC {
                ioc_type: IoCType::Email,
                value: "attacker@malicious.com".to_string(),
                context: Some("Sender email".to_string()),
                score: Some(0.95),
            }],
            recommendations: vec![
                "Block sender domain".to_string(),
                "Alert affected user".to_string(),
            ],
            risk_score: 85,
            analyzed_by: "AI Agent v1".to_string(),
            timestamp: Utc::now(),
            evidence: vec![],
            investigation_steps: vec![],
        });

        incident
    }

    #[test]
    fn test_incident_text_serialization() {
        let incident = create_test_incident();
        let serializer = IncidentTextSerializer::new();
        let text = serializer.serialize(&incident);

        assert!(text.contains("Security Incident"));
        assert!(text.contains("High"));
        assert!(text.contains("Suspected phishing email"));
        assert!(text.contains("sender: attacker@malicious.com"));
        assert!(text.contains("phishing"));
    }

    #[test]
    fn test_incident_text_serialization_with_analysis() {
        let incident = create_incident_with_analysis();
        let serializer = IncidentTextSerializer::new();
        let text = serializer.serialize(&incident);

        assert!(text.contains("Analysis Results"));
        assert!(text.contains("TruePositive"));
        assert!(text.contains("T1566.001"));
        assert!(text.contains("Spearphishing Attachment"));
        assert!(text.contains("Block sender domain"));
    }

    #[test]
    fn test_text_truncation() {
        let mut incident = create_test_incident();
        // Add a very long description
        incident.alert_data = serde_json::json!({
            "description": "x".repeat(MAX_TEXT_LENGTH + 1000)
        });

        let serializer = IncidentTextSerializer::new();
        let text = serializer.serialize(&incident);

        assert!(text.len() <= MAX_TEXT_LENGTH);
    }

    #[test]
    fn test_incident_metadata_creation() {
        let incident = create_incident_with_analysis();
        let metadata = IncidentMetadata::from_incident(&incident);

        assert_eq!(metadata.doc_type, "incident");
        assert_eq!(metadata.severity, "high");
        assert_eq!(metadata.source_type, "email_security");
        assert_eq!(metadata.verdict, Some("TruePositive".to_string()));
        assert!(metadata.confidence.unwrap() > 0.9);
        assert!(metadata.mitre_techniques.contains(&"T1566.001".to_string()));
    }

    #[test]
    fn test_mock_embedder() {
        let embedder = MockEmbedder::new(384);

        // Test determinism
        let embedding1 = embedder.generate_embedding("test text");
        let embedding2 = embedder.generate_embedding("test text");
        assert_eq!(embedding1, embedding2);

        // Test dimension
        assert_eq!(embedding1.len(), 384);

        // Test normalization (magnitude should be ~1.0)
        let magnitude: f32 = embedding1.iter().map(|x| x * x).sum::<f32>().sqrt();
        assert!((magnitude - 1.0).abs() < 0.001);
    }

    #[tokio::test]
    async fn test_embedding_service_initialization() {
        let vector_store = Arc::new(MockVectorStore::new());
        let embedder = Arc::new(MockEmbedder::new(384));
        let config = EmbeddingConfig::new(384);

        let service = IncidentEmbeddingService::new(vector_store.clone(), embedder, config);

        // Initialize should create the collection
        service.initialize().await.unwrap();

        // Collection should exist
        assert!(vector_store
            .collection_exists(INCIDENTS_COLLECTION)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn test_index_and_search_incident() {
        let vector_store = Arc::new(MockVectorStore::new());
        let embedder = Arc::new(MockEmbedder::new(384));
        let config = EmbeddingConfig::new(384);

        let service = IncidentEmbeddingService::new(vector_store.clone(), embedder, config);
        service.initialize().await.unwrap();

        // Index an incident
        let incident = create_incident_with_analysis();
        service.index_incident(&incident).await.unwrap();

        // Verify it's stored
        let record = vector_store
            .get(INCIDENTS_COLLECTION, &incident.id.to_string())
            .await
            .unwrap();
        assert!(record.is_some());

        let record = record.unwrap();
        assert_eq!(record.id, incident.id.to_string());
        assert_eq!(record.metadata.get_str("doc_type"), Some("incident"));
        assert_eq!(record.metadata.get_str("severity"), Some("high"));
    }

    #[tokio::test]
    async fn test_find_similar_incidents() {
        let vector_store = Arc::new(MockVectorStore::new());
        let embedder = Arc::new(MockEmbedder::new(384));
        let config = EmbeddingConfig::new(384);

        let service = IncidentEmbeddingService::new(vector_store.clone(), embedder, config);
        service.initialize().await.unwrap();

        // Index multiple incidents
        let incident1 = create_test_incident();
        let mut incident2 = create_test_incident();
        incident2.id = Uuid::new_v4();

        service.index_incident(&incident1).await.unwrap();
        service.index_incident(&incident2).await.unwrap();

        // Search for similar
        let similar = service.find_similar(&incident1, 5).await.unwrap();

        // Should find incident2 (incident1 is excluded)
        assert!(!similar.is_empty());
        assert!(similar.iter().any(|s| s.incident_id == incident2.id));
        assert!(!similar.iter().any(|s| s.incident_id == incident1.id));
    }

    #[tokio::test]
    async fn test_batch_indexing() {
        let vector_store = Arc::new(MockVectorStore::new());
        let embedder = Arc::new(MockEmbedder::new(384));
        let config = EmbeddingConfig::new(384).with_batch_size(2);

        let service = IncidentEmbeddingService::new(vector_store.clone(), embedder, config);
        service.initialize().await.unwrap();

        // Create multiple incidents
        let incidents: Vec<Incident> = (0..5)
            .map(|_| {
                let mut inc = create_test_incident();
                inc.id = Uuid::new_v4();
                inc
            })
            .collect();

        // Index in batch
        let stats = service.index_incidents(&incidents).await.unwrap();

        assert_eq!(stats.indexed, 5);
        assert_eq!(stats.failed, 0);

        // Verify all are stored
        let info = vector_store
            .collection_info(INCIDENTS_COLLECTION)
            .await
            .unwrap();
        assert_eq!(info.vectors_count, 5);
    }

    #[tokio::test]
    async fn test_delete_incident() {
        let vector_store = Arc::new(MockVectorStore::new());
        let embedder = Arc::new(MockEmbedder::new(384));
        let config = EmbeddingConfig::new(384);

        let service = IncidentEmbeddingService::new(vector_store.clone(), embedder, config);
        service.initialize().await.unwrap();

        let incident = create_test_incident();
        service.index_incident(&incident).await.unwrap();

        // Verify it exists
        let record = vector_store
            .get(INCIDENTS_COLLECTION, &incident.id.to_string())
            .await
            .unwrap();
        assert!(record.is_some());

        // Delete
        service.delete_incident(incident.id).await.unwrap();

        // Verify it's gone
        let record = vector_store
            .get(INCIDENTS_COLLECTION, &incident.id.to_string())
            .await
            .unwrap();
        assert!(record.is_none());
    }

    #[tokio::test]
    async fn test_find_similar_by_text() {
        let vector_store = Arc::new(MockVectorStore::new());
        let embedder = Arc::new(MockEmbedder::new(384));
        let config = EmbeddingConfig::new(384);

        let service = IncidentEmbeddingService::new(vector_store.clone(), embedder, config);
        service.initialize().await.unwrap();

        // Index an incident
        let incident = create_incident_with_analysis();
        service.index_incident(&incident).await.unwrap();

        // Search by text query
        let similar = service
            .find_similar_by_text("phishing email credential theft", 5, None)
            .await
            .unwrap();

        // Should find the indexed incident
        assert!(!similar.is_empty());
    }

    #[test]
    fn test_embedding_config_builder() {
        let config = EmbeddingConfig::new(768)
            .with_collection_name("custom_incidents")
            .with_on_disk(true)
            .with_batch_size(50);

        assert_eq!(config.dimension, 768);
        assert_eq!(config.collection_name, "custom_incidents");
        assert!(config.on_disk);
        assert_eq!(config.batch_size, 50);
    }
}
