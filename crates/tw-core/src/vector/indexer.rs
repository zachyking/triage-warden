//! Event-driven incident indexer for real-time RAG updates.
//!
//! This module provides a background service that listens to triage events
//! and automatically updates incident embeddings in the vector store.
//!
//! # Event Handling
//!
//! The indexer responds to the following events:
//!
//! | Event | Action |
//! |-------|--------|
//! | `IncidentCreated` | Index the new incident |
//! | `AnalysisComplete` | Re-index with updated analysis |
//! | `EnrichmentComplete` | Queue for re-indexing (batched) |
//! | `StatusChanged` | Update metadata only |
//! | `IncidentResolved` | Update metadata with resolution |
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────┐    ┌─────────────┐    ┌─────────────────┐    ┌─────────────┐
//! │  EventBus   │───►│  Indexer    │───►│  Embedding      │───►│  Vector     │
//! │             │    │  (listener) │    │  Service        │    │  Store      │
//! └─────────────┘    └─────────────┘    └─────────────────┘    └─────────────┘
//!                          │
//!                          ▼
//!                    ┌─────────────┐
//!                    │  Incident   │
//!                    │  Repository │
//!                    └─────────────┘
//! ```
//!
//! # Usage
//!
//! ```ignore
//! use tw_core::vector::indexer::IncidentIndexer;
//!
//! // Create the indexer
//! let indexer = IncidentIndexer::new(
//!     embedding_service,
//!     incident_repository,
//!     config,
//! );
//!
//! // Start listening to events
//! let handle = indexer.start(event_bus.subscribe_broadcast()).await;
//!
//! // Stop when done
//! handle.stop().await;
//! ```

use crate::events::TriageEvent;
use crate::incident::Incident;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc, oneshot, RwLock};
use tracing::{debug, error, info, instrument, warn};
use uuid::Uuid;

use super::embeddings::{Embedder, EmbeddingError, EmbeddingResult, IncidentEmbeddingService};
use super::VectorStore;

/// Configuration for the incident indexer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexerConfig {
    /// How long to wait before re-indexing after enrichment (allows batching).
    #[serde(with = "humantime_serde", default = "default_enrichment_delay")]
    pub enrichment_delay: std::time::Duration,

    /// Maximum number of pending re-index operations before force flush.
    #[serde(default = "default_max_pending")]
    pub max_pending: usize,

    /// Whether to index incidents on creation.
    #[serde(default = "default_true")]
    pub index_on_create: bool,

    /// Whether to re-index when analysis completes.
    #[serde(default = "default_true")]
    pub index_on_analysis: bool,

    /// Whether to re-index when enrichments complete.
    #[serde(default = "default_true")]
    pub index_on_enrichment: bool,

    /// Whether to update metadata when status changes.
    #[serde(default = "default_true")]
    pub update_on_status_change: bool,

    /// Channel buffer size for the indexer.
    #[serde(default = "default_buffer_size")]
    pub buffer_size: usize,
}

fn default_enrichment_delay() -> std::time::Duration {
    std::time::Duration::from_secs(5)
}

fn default_max_pending() -> usize {
    100
}

fn default_true() -> bool {
    true
}

fn default_buffer_size() -> usize {
    1024
}

impl Default for IndexerConfig {
    fn default() -> Self {
        Self {
            enrichment_delay: default_enrichment_delay(),
            max_pending: default_max_pending(),
            index_on_create: true,
            index_on_analysis: true,
            index_on_enrichment: true,
            update_on_status_change: true,
            buffer_size: default_buffer_size(),
        }
    }
}

/// Statistics for the indexer.
#[derive(Debug, Clone, Default)]
pub struct IndexerStats {
    /// Total incidents indexed.
    pub total_indexed: u64,
    /// Incidents indexed on creation.
    pub indexed_on_create: u64,
    /// Incidents re-indexed on analysis.
    pub indexed_on_analysis: u64,
    /// Incidents re-indexed on enrichment.
    pub indexed_on_enrichment: u64,
    /// Metadata updates on status change.
    pub metadata_updates: u64,
    /// Failed indexing operations.
    pub failed: u64,
    /// Pending re-index operations (enrichment batching).
    pub pending: u64,
}

/// Command for the indexer task.
#[derive(Debug)]
enum IndexerCommand {
    /// Index or re-index an incident.
    Index {
        incident_id: Uuid,
        reason: IndexReason,
    },
    /// Stop the indexer.
    Stop(oneshot::Sender<()>),
    /// Get current stats.
    GetStats(oneshot::Sender<IndexerStats>),
    /// Force flush pending operations.
    Flush,
}

/// Reason for indexing an incident.
#[derive(Debug, Clone, Copy)]
enum IndexReason {
    /// Newly created incident.
    Created,
    /// Analysis was completed.
    AnalysisComplete,
    /// Enrichment was added.
    EnrichmentAdded,
    /// Status changed.
    StatusChanged,
    /// Manual re-index request.
    Manual,
}

/// Handle for controlling the indexer.
pub struct IndexerHandle {
    command_tx: mpsc::Sender<IndexerCommand>,
}

impl IndexerHandle {
    /// Stop the indexer and wait for it to finish.
    pub async fn stop(self) {
        let (tx, rx) = oneshot::channel();
        if self.command_tx.send(IndexerCommand::Stop(tx)).await.is_ok() {
            let _ = rx.await;
        }
    }

    /// Get current indexer statistics.
    pub async fn stats(&self) -> Option<IndexerStats> {
        let (tx, rx) = oneshot::channel();
        if self
            .command_tx
            .send(IndexerCommand::GetStats(tx))
            .await
            .is_ok()
        {
            rx.await.ok()
        } else {
            None
        }
    }

    /// Force flush pending re-index operations.
    pub async fn flush(&self) {
        let _ = self.command_tx.send(IndexerCommand::Flush).await;
    }

    /// Request re-indexing of a specific incident.
    pub async fn reindex(&self, incident_id: Uuid) {
        let _ = self
            .command_tx
            .send(IndexerCommand::Index {
                incident_id,
                reason: IndexReason::Manual,
            })
            .await;
    }
}

/// Event-driven incident indexer.
///
/// Listens to triage events and automatically updates incident embeddings
/// in the vector store for RAG functionality.
pub struct IncidentIndexer<V, E, R>
where
    V: VectorStore + 'static,
    E: Embedder + 'static,
    R: IncidentRepository + 'static,
{
    /// Embedding service for generating and storing vectors.
    embedding_service: Arc<IncidentEmbeddingService<V, E>>,
    /// Incident repository for fetching incident data.
    incident_repo: Arc<R>,
    /// Configuration.
    config: IndexerConfig,
    /// Statistics.
    stats: Arc<RwLock<IndexerStats>>,
    /// Pending re-index operations (for enrichment batching).
    pending_reindex: Arc<RwLock<HashMap<Uuid, DateTime<Utc>>>>,
}

/// Trait for fetching incidents (to support different repository types).
#[async_trait::async_trait]
pub trait IncidentRepository: Send + Sync {
    /// Get an incident by ID.
    async fn get_incident(&self, id: Uuid) -> Result<Option<Incident>, EmbeddingError>;
}

impl<V, E, R> IncidentIndexer<V, E, R>
where
    V: VectorStore + 'static,
    E: Embedder + 'static,
    R: IncidentRepository + 'static,
{
    /// Create a new incident indexer.
    pub fn new(
        embedding_service: Arc<IncidentEmbeddingService<V, E>>,
        incident_repo: Arc<R>,
        config: IndexerConfig,
    ) -> Self {
        Self {
            embedding_service,
            incident_repo,
            config,
            stats: Arc::new(RwLock::new(IndexerStats::default())),
            pending_reindex: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Start the indexer, listening to events from a broadcast channel.
    ///
    /// Returns a handle that can be used to control the indexer.
    pub fn start(self: Arc<Self>, mut event_rx: broadcast::Receiver<TriageEvent>) -> IndexerHandle {
        let (command_tx, mut command_rx) = mpsc::channel::<IndexerCommand>(self.config.buffer_size);

        let indexer = Arc::clone(&self);
        let command_tx_clone = command_tx.clone();

        // Spawn the main indexer task
        tokio::spawn(async move {
            let mut flush_interval = tokio::time::interval(indexer.config.enrichment_delay);

            loop {
                tokio::select! {
                    // Handle incoming events
                    event = event_rx.recv() => {
                        match event {
                            Ok(event) => {
                                indexer.handle_event(&event, &command_tx_clone).await;
                            }
                            Err(broadcast::error::RecvError::Lagged(n)) => {
                                warn!("Indexer lagged behind by {} events", n);
                            }
                            Err(broadcast::error::RecvError::Closed) => {
                                info!("Event channel closed, shutting down indexer");
                                break;
                            }
                        }
                    }

                    // Handle commands
                    Some(command) = command_rx.recv() => {
                        match command {
                            IndexerCommand::Stop(done) => {
                                info!("Stopping incident indexer");
                                // Flush pending before stopping
                                indexer.flush_pending().await;
                                let _ = done.send(());
                                break;
                            }
                            IndexerCommand::GetStats(sender) => {
                                let stats = indexer.stats.read().await.clone();
                                let _ = sender.send(stats);
                            }
                            IndexerCommand::Index { incident_id, reason } => {
                                indexer.index_incident(incident_id, reason).await;
                            }
                            IndexerCommand::Flush => {
                                indexer.flush_pending().await;
                            }
                        }
                    }

                    // Periodic flush of pending re-index operations
                    _ = flush_interval.tick() => {
                        indexer.check_and_flush_pending().await;
                    }
                }
            }

            info!("Incident indexer stopped");
        });

        IndexerHandle { command_tx }
    }

    /// Handle a triage event.
    async fn handle_event(&self, event: &TriageEvent, command_tx: &mpsc::Sender<IndexerCommand>) {
        match event {
            TriageEvent::IncidentCreated { incident_id, .. } if self.config.index_on_create => {
                debug!(incident_id = %incident_id, "Incident created, queuing for indexing");
                let _ = command_tx
                    .send(IndexerCommand::Index {
                        incident_id: *incident_id,
                        reason: IndexReason::Created,
                    })
                    .await;
            }

            TriageEvent::AnalysisComplete { incident_id, .. } if self.config.index_on_analysis => {
                debug!(incident_id = %incident_id, "Analysis complete, queuing for re-indexing");
                let _ = command_tx
                    .send(IndexerCommand::Index {
                        incident_id: *incident_id,
                        reason: IndexReason::AnalysisComplete,
                    })
                    .await;
            }

            TriageEvent::EnrichmentComplete { incident_id, .. }
                if self.config.index_on_enrichment =>
            {
                debug!(incident_id = %incident_id, "Enrichment complete, adding to pending batch");
                // Add to pending set (will be batched)
                self.add_pending(*incident_id).await;
            }

            TriageEvent::StatusChanged { incident_id, .. }
                if self.config.update_on_status_change =>
            {
                debug!(incident_id = %incident_id, "Status changed, queuing for metadata update");
                let _ = command_tx
                    .send(IndexerCommand::Index {
                        incident_id: *incident_id,
                        reason: IndexReason::StatusChanged,
                    })
                    .await;
            }

            TriageEvent::IncidentResolved { incident_id, .. } => {
                debug!(incident_id = %incident_id, "Incident resolved, queuing for final update");
                let _ = command_tx
                    .send(IndexerCommand::Index {
                        incident_id: *incident_id,
                        reason: IndexReason::StatusChanged,
                    })
                    .await;
            }

            _ => {
                // Ignore other events
            }
        }
    }

    /// Add an incident to the pending re-index set.
    async fn add_pending(&self, incident_id: Uuid) {
        let mut pending = self.pending_reindex.write().await;
        pending.insert(incident_id, Utc::now());

        // Update stats
        let mut stats = self.stats.write().await;
        stats.pending = pending.len() as u64;

        // Force flush if we've hit the max
        if pending.len() >= self.config.max_pending {
            drop(pending);
            drop(stats);
            self.flush_pending().await;
        }
    }

    /// Check if any pending operations are ready to flush.
    async fn check_and_flush_pending(&self) {
        let cutoff = Utc::now()
            - Duration::from_std(self.config.enrichment_delay).unwrap_or(Duration::seconds(5));

        let ready: Vec<Uuid> = {
            let pending = self.pending_reindex.read().await;
            pending
                .iter()
                .filter(|(_, ts)| **ts <= cutoff)
                .map(|(id, _)| *id)
                .collect()
        };

        if ready.is_empty() {
            return;
        }

        debug!(
            count = ready.len(),
            "Flushing ready pending re-index operations"
        );

        for incident_id in ready {
            self.index_incident(incident_id, IndexReason::EnrichmentAdded)
                .await;
            self.pending_reindex.write().await.remove(&incident_id);
        }

        // Update pending count
        let mut stats = self.stats.write().await;
        stats.pending = self.pending_reindex.read().await.len() as u64;
    }

    /// Flush all pending re-index operations immediately.
    async fn flush_pending(&self) {
        let pending: Vec<Uuid> = {
            let mut pending = self.pending_reindex.write().await;
            let ids: Vec<Uuid> = pending.keys().cloned().collect();
            pending.clear();
            ids
        };

        if pending.is_empty() {
            return;
        }

        info!(
            count = pending.len(),
            "Force flushing all pending re-index operations"
        );

        for incident_id in pending {
            self.index_incident(incident_id, IndexReason::EnrichmentAdded)
                .await;
        }

        // Update pending count
        let mut stats = self.stats.write().await;
        stats.pending = 0;
    }

    /// Index or re-index a single incident.
    #[instrument(skip(self), fields(incident_id = %incident_id, reason = ?reason))]
    async fn index_incident(&self, incident_id: Uuid, reason: IndexReason) {
        // Fetch the incident
        let incident = match self.incident_repo.get_incident(incident_id).await {
            Ok(Some(incident)) => incident,
            Ok(None) => {
                warn!(incident_id = %incident_id, "Incident not found for indexing");
                return;
            }
            Err(e) => {
                error!(incident_id = %incident_id, error = %e, "Failed to fetch incident for indexing");
                self.record_failure().await;
                return;
            }
        };

        // Index the incident
        if let Err(e) = self.embedding_service.index_incident(&incident).await {
            error!(incident_id = %incident_id, error = %e, "Failed to index incident");
            self.record_failure().await;
            return;
        }

        // Update stats
        let mut stats = self.stats.write().await;
        stats.total_indexed += 1;

        match reason {
            IndexReason::Created => stats.indexed_on_create += 1,
            IndexReason::AnalysisComplete => stats.indexed_on_analysis += 1,
            IndexReason::EnrichmentAdded => stats.indexed_on_enrichment += 1,
            IndexReason::StatusChanged => stats.metadata_updates += 1,
            IndexReason::Manual => {}
        }

        debug!(incident_id = %incident_id, reason = ?reason, "Successfully indexed incident");
    }

    /// Record a failed indexing operation.
    async fn record_failure(&self) {
        let mut stats = self.stats.write().await;
        stats.failed += 1;
    }
}

/// Batch indexer for bulk importing existing incidents.
///
/// Used during startup/migration to index all existing incidents.
pub struct BatchIndexer<V, E>
where
    V: VectorStore + 'static,
    E: Embedder + 'static,
{
    embedding_service: Arc<IncidentEmbeddingService<V, E>>,
}

impl<V, E> BatchIndexer<V, E>
where
    V: VectorStore + 'static,
    E: Embedder + 'static,
{
    /// Create a new batch indexer.
    pub fn new(embedding_service: Arc<IncidentEmbeddingService<V, E>>) -> Self {
        Self { embedding_service }
    }

    /// Index all incidents from an iterator.
    ///
    /// Returns statistics about the indexing operation.
    #[instrument(skip(self, incidents))]
    pub async fn index_all<I>(&self, incidents: I) -> EmbeddingResult<BatchIndexStats>
    where
        I: IntoIterator<Item = Incident>,
    {
        let incidents: Vec<Incident> = incidents.into_iter().collect();
        let total = incidents.len();

        info!(
            total = total,
            "Starting batch indexing of existing incidents"
        );

        let stats = self.embedding_service.index_incidents(&incidents).await?;

        info!(
            indexed = stats.indexed,
            failed = stats.failed,
            total = total,
            "Completed batch indexing"
        );

        Ok(BatchIndexStats {
            total,
            indexed: stats.indexed,
            failed: stats.failed,
        })
    }

    /// Initialize the collection and index all incidents.
    ///
    /// This is the recommended method to call during startup.
    #[instrument(skip(self, incidents))]
    pub async fn initialize_and_index<I>(&self, incidents: I) -> EmbeddingResult<BatchIndexStats>
    where
        I: IntoIterator<Item = Incident>,
    {
        // Initialize the collection
        self.embedding_service.initialize().await?;

        // Check current state
        let stats = self.embedding_service.get_stats().await?;
        if stats.vector_count > 0 {
            info!(
                vector_count = stats.vector_count,
                "Collection already has vectors, skipping full re-index"
            );
            return Ok(BatchIndexStats {
                total: 0,
                indexed: 0,
                failed: 0,
            });
        }

        // Index all incidents
        self.index_all(incidents).await
    }
}

/// Statistics from batch indexing.
#[derive(Debug, Clone, Default)]
pub struct BatchIndexStats {
    /// Total incidents processed.
    pub total: usize,
    /// Successfully indexed.
    pub indexed: usize,
    /// Failed to index.
    pub failed: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::incident::{Alert, AlertSource, Severity};
    use crate::vector::embeddings::{EmbeddingConfig, MockEmbedder};
    use crate::vector::MockVectorStore;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Mock incident repository for testing.
    struct MockIncidentRepository {
        incidents: RwLock<HashMap<Uuid, Incident>>,
        get_count: AtomicU64,
    }

    impl MockIncidentRepository {
        fn new() -> Self {
            Self {
                incidents: RwLock::new(HashMap::new()),
                get_count: AtomicU64::new(0),
            }
        }

        async fn add_incident(&self, incident: Incident) {
            self.incidents.write().await.insert(incident.id, incident);
        }
    }

    #[async_trait::async_trait]
    impl IncidentRepository for MockIncidentRepository {
        async fn get_incident(&self, id: Uuid) -> Result<Option<Incident>, EmbeddingError> {
            self.get_count.fetch_add(1, Ordering::Relaxed);
            Ok(self.incidents.read().await.get(&id).cloned())
        }
    }

    fn create_test_incident() -> Incident {
        let alert = Alert {
            id: "test-alert".to_string(),
            source: AlertSource::EmailSecurity("M365".to_string()),
            alert_type: "phishing".to_string(),
            severity: Severity::High,
            title: "Test Alert".to_string(),
            description: None,
            data: serde_json::json!({}),
            timestamp: Utc::now(),
            tags: vec![],
        };
        let mut incident = Incident::from_alert(alert);
        incident.id = Uuid::new_v4();
        incident
    }

    #[tokio::test]
    async fn test_indexer_config_defaults() {
        let config = IndexerConfig::default();

        assert!(config.index_on_create);
        assert!(config.index_on_analysis);
        assert!(config.index_on_enrichment);
        assert!(config.update_on_status_change);
        assert_eq!(config.max_pending, 100);
    }

    #[tokio::test]
    async fn test_batch_indexer_initialize() {
        let vector_store = Arc::new(MockVectorStore::new());
        let embedder = Arc::new(MockEmbedder::new(384));
        let config = EmbeddingConfig::new(384);

        let embedding_service = Arc::new(IncidentEmbeddingService::new(
            vector_store.clone(),
            embedder,
            config,
        ));

        let batch_indexer = BatchIndexer::new(embedding_service);

        // Create test incidents
        let incidents: Vec<Incident> = (0..5).map(|_| create_test_incident()).collect();

        // Initialize and index
        let stats = batch_indexer
            .initialize_and_index(incidents.clone())
            .await
            .unwrap();

        assert_eq!(stats.total, 5);
        assert_eq!(stats.indexed, 5);
        assert_eq!(stats.failed, 0);

        // Verify vectors are in the store
        let info = vector_store.collection_info("incidents").await.unwrap();
        assert_eq!(info.vectors_count, 5);
    }

    #[tokio::test]
    async fn test_batch_indexer_skips_if_already_indexed() {
        let vector_store = Arc::new(MockVectorStore::new());
        let embedder = Arc::new(MockEmbedder::new(384));
        let config = EmbeddingConfig::new(384);

        let embedding_service = Arc::new(IncidentEmbeddingService::new(
            vector_store.clone(),
            embedder,
            config,
        ));

        let batch_indexer = BatchIndexer::new(Arc::clone(&embedding_service));

        // First initialization
        let incidents1: Vec<Incident> = (0..3).map(|_| create_test_incident()).collect();
        let stats1 = batch_indexer
            .initialize_and_index(incidents1)
            .await
            .unwrap();
        assert_eq!(stats1.indexed, 3);

        // Second initialization should skip
        let incidents2: Vec<Incident> = (0..5).map(|_| create_test_incident()).collect();
        let stats2 = batch_indexer
            .initialize_and_index(incidents2)
            .await
            .unwrap();
        assert_eq!(stats2.indexed, 0); // Skipped because collection already has vectors
    }

    #[tokio::test]
    async fn test_indexer_handle_stats() {
        let vector_store = Arc::new(MockVectorStore::new());
        let embedder = Arc::new(MockEmbedder::new(384));
        let config = EmbeddingConfig::new(384);

        let embedding_service = Arc::new(IncidentEmbeddingService::new(
            vector_store.clone(),
            embedder,
            config,
        ));
        embedding_service.initialize().await.unwrap();

        let incident_repo = Arc::new(MockIncidentRepository::new());
        let indexer_config = IndexerConfig::default();

        let indexer = Arc::new(IncidentIndexer::new(
            embedding_service,
            incident_repo,
            indexer_config,
        ));

        // Create a dummy broadcast channel
        let (tx, rx) = broadcast::channel::<TriageEvent>(16);
        let handle = indexer.start(rx);

        // Get initial stats
        let stats = handle.stats().await.unwrap();
        assert_eq!(stats.total_indexed, 0);

        // Clean up
        drop(tx);
        handle.stop().await;
    }

    #[tokio::test]
    async fn test_indexer_manual_reindex() {
        let vector_store = Arc::new(MockVectorStore::new());
        let embedder = Arc::new(MockEmbedder::new(384));
        let config = EmbeddingConfig::new(384);

        let embedding_service = Arc::new(IncidentEmbeddingService::new(
            vector_store.clone(),
            embedder,
            config,
        ));
        embedding_service.initialize().await.unwrap();

        let incident_repo = Arc::new(MockIncidentRepository::new());
        let incident = create_test_incident();
        incident_repo.add_incident(incident.clone()).await;

        let indexer_config = IndexerConfig::default();

        let indexer = Arc::new(IncidentIndexer::new(
            embedding_service,
            Arc::clone(&incident_repo),
            indexer_config,
        ));

        let (tx, rx) = broadcast::channel::<TriageEvent>(16);
        let handle = indexer.start(rx);

        // Manual reindex request
        handle.reindex(incident.id).await;

        // Give it time to process
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Check stats
        let stats = handle.stats().await.unwrap();
        assert_eq!(stats.total_indexed, 1);

        // Clean up
        drop(tx);
        handle.stop().await;
    }

    #[tokio::test]
    async fn test_indexer_event_handling() {
        let vector_store = Arc::new(MockVectorStore::new());
        let embedder = Arc::new(MockEmbedder::new(384));
        let config = EmbeddingConfig::new(384);

        let embedding_service = Arc::new(IncidentEmbeddingService::new(
            vector_store.clone(),
            embedder,
            config,
        ));
        embedding_service.initialize().await.unwrap();

        let incident_repo = Arc::new(MockIncidentRepository::new());
        let incident = create_test_incident();
        incident_repo.add_incident(incident.clone()).await;

        let indexer_config = IndexerConfig::default();

        let indexer = Arc::new(IncidentIndexer::new(
            embedding_service,
            Arc::clone(&incident_repo),
            indexer_config,
        ));

        let (tx, rx) = broadcast::channel::<TriageEvent>(16);
        let handle = indexer.start(rx);

        // Send an IncidentCreated event
        tx.send(TriageEvent::IncidentCreated {
            incident_id: incident.id,
            alert_id: "test-alert".to_string(),
        })
        .unwrap();

        // Give it time to process
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Check that the incident was indexed
        let stats = handle.stats().await.unwrap();
        assert_eq!(stats.total_indexed, 1);
        assert_eq!(stats.indexed_on_create, 1);

        // Verify it's in the vector store
        let record = vector_store
            .get("incidents", &incident.id.to_string())
            .await
            .unwrap();
        assert!(record.is_some());

        // Clean up
        drop(tx);
        handle.stop().await;
    }
}
