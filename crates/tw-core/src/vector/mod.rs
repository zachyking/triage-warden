//! Vector store abstraction for RAG (Retrieval Augmented Generation).
//!
//! This module provides a trait-based abstraction for vector databases,
//! enabling semantic search over embeddings for:
//! - Similar incident retrieval
//! - Knowledge base (runbooks, threat intel) search
//! - Security playbook matching
//!
//! # Feature Flags
//!
//! - `vector-store`: Enables the Qdrant implementation
//!
//! # Example
//!
//! ```ignore
//! use tw_core::vector::{VectorStore, SearchResult, VectorMetadata};
//! use serde_json::json;
//!
//! async fn search_similar_incidents(
//!     store: &impl VectorStore,
//!     embedding: &[f32],
//! ) -> anyhow::Result<Vec<SearchResult>> {
//!     store.search(
//!         "incidents",
//!         embedding,
//!         5,
//!         Some(json!({"status": "resolved"})),
//!     ).await
//! }
//! ```

mod embeddings;
mod error;
mod indexer;
mod mock;
mod types;

#[cfg(feature = "vector-store")]
mod qdrant;

pub use embeddings::{
    CollectionStats, Embedder, EmbeddingConfig, EmbeddingError, EmbeddingResult,
    IncidentEmbeddingService, IncidentMetadata, IncidentTextSerializer, IndexStats, MockEmbedder,
    SimilarIncident, DEFAULT_EMBEDDING_DIMENSION, INCIDENTS_COLLECTION, MAX_TEXT_LENGTH,
};
pub use error::{VectorStoreError, VectorStoreResult};
pub use indexer::{
    BatchIndexStats, BatchIndexer, IncidentIndexer, IncidentRepository as IncidentRepoForIndexer,
    IndexerConfig, IndexerHandle, IndexerStats,
};
pub use mock::MockVectorStore;
pub use types::{
    CollectionConfig, CollectionInfo, DistanceMetric, SearchFilter, SearchResult, VectorMetadata,
    VectorRecord,
};

#[cfg(feature = "vector-store")]
pub use qdrant::{QdrantConfig, QdrantVectorStore};

use async_trait::async_trait;

/// Trait for vector store implementations.
///
/// Provides a unified interface for vector database operations including:
/// - Collection management (create, delete, info)
/// - Document operations (upsert, delete)
/// - Semantic search with optional filtering
///
/// Implementations must be thread-safe (`Send + Sync`).
#[async_trait]
pub trait VectorStore: Send + Sync {
    /// Create a new collection with the specified configuration.
    ///
    /// # Arguments
    ///
    /// * `name` - The collection name (must be unique)
    /// * `config` - Collection configuration including vector dimensions
    ///
    /// # Errors
    ///
    /// Returns an error if the collection already exists or creation fails.
    async fn create_collection(
        &self,
        name: &str,
        config: CollectionConfig,
    ) -> VectorStoreResult<()>;

    /// Delete a collection and all its vectors.
    ///
    /// # Arguments
    ///
    /// * `name` - The collection name to delete
    ///
    /// # Errors
    ///
    /// Returns an error if the collection doesn't exist or deletion fails.
    async fn delete_collection(&self, name: &str) -> VectorStoreResult<()>;

    /// Get information about a collection.
    ///
    /// # Arguments
    ///
    /// * `name` - The collection name
    ///
    /// # Returns
    ///
    /// Collection metadata including vector count and configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the collection doesn't exist.
    async fn collection_info(&self, name: &str) -> VectorStoreResult<CollectionInfo>;

    /// Check if a collection exists.
    ///
    /// # Arguments
    ///
    /// * `name` - The collection name to check
    async fn collection_exists(&self, name: &str) -> VectorStoreResult<bool>;

    /// Insert or update a vector with associated metadata.
    ///
    /// If a vector with the same ID already exists, it will be replaced.
    ///
    /// # Arguments
    ///
    /// * `collection` - The target collection name
    /// * `id` - Unique identifier for the vector
    /// * `embedding` - The vector embedding (must match collection dimensions)
    /// * `metadata` - Associated metadata for filtering and retrieval
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The collection doesn't exist
    /// - The embedding dimensions don't match the collection
    /// - The operation fails
    async fn upsert(
        &self,
        collection: &str,
        id: &str,
        embedding: &[f32],
        metadata: VectorMetadata,
    ) -> VectorStoreResult<()>;

    /// Insert or update multiple vectors in a batch.
    ///
    /// More efficient than individual upserts for bulk operations.
    ///
    /// # Arguments
    ///
    /// * `collection` - The target collection name
    /// * `records` - Vector records to upsert
    ///
    /// # Errors
    ///
    /// Returns an error if any record fails validation or the operation fails.
    async fn upsert_batch(
        &self,
        collection: &str,
        records: Vec<VectorRecord>,
    ) -> VectorStoreResult<()>;

    /// Search for similar vectors using cosine/dot product similarity.
    ///
    /// # Arguments
    ///
    /// * `collection` - The collection to search
    /// * `embedding` - Query vector embedding
    /// * `top_k` - Maximum number of results to return
    /// * `filter` - Optional metadata filter (JSON value for filtering)
    ///
    /// # Returns
    ///
    /// Ordered list of search results, sorted by similarity (highest first).
    ///
    /// # Errors
    ///
    /// Returns an error if the collection doesn't exist or search fails.
    async fn search(
        &self,
        collection: &str,
        embedding: &[f32],
        top_k: usize,
        filter: Option<SearchFilter>,
    ) -> VectorStoreResult<Vec<SearchResult>>;

    /// Delete a vector by ID.
    ///
    /// # Arguments
    ///
    /// * `collection` - The collection containing the vector
    /// * `id` - The vector ID to delete
    ///
    /// # Errors
    ///
    /// Returns an error if the collection doesn't exist or deletion fails.
    /// Note: Deleting a non-existent ID is not considered an error.
    async fn delete(&self, collection: &str, id: &str) -> VectorStoreResult<()>;

    /// Delete multiple vectors by ID.
    ///
    /// # Arguments
    ///
    /// * `collection` - The collection containing the vectors
    /// * `ids` - The vector IDs to delete
    ///
    /// # Errors
    ///
    /// Returns an error if the collection doesn't exist or deletion fails.
    async fn delete_batch(&self, collection: &str, ids: &[&str]) -> VectorStoreResult<()>;

    /// Get a vector by ID.
    ///
    /// # Arguments
    ///
    /// * `collection` - The collection containing the vector
    /// * `id` - The vector ID to retrieve
    ///
    /// # Returns
    ///
    /// The vector record if found, or None if not found.
    async fn get(&self, collection: &str, id: &str) -> VectorStoreResult<Option<VectorRecord>>;

    /// Check the health of the vector store connection.
    ///
    /// # Returns
    ///
    /// `true` if the connection is healthy, `false` otherwise.
    async fn health_check(&self) -> bool;
}

/// Type alias for a boxed dynamic vector store.
pub type DynVectorStore = Box<dyn VectorStore>;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn test_mock_vector_store_basic_operations() {
        let store = MockVectorStore::new();

        // Create collection
        let config = CollectionConfig {
            dimension: 384,
            distance: DistanceMetric::Cosine,
            on_disk: false,
        };
        store.create_collection("test", config).await.unwrap();

        // Verify collection exists
        assert!(store.collection_exists("test").await.unwrap());

        // Upsert a vector
        let embedding = vec![0.1; 384];
        let metadata = VectorMetadata::new()
            .with_field("type", json!("incident"))
            .with_field("severity", json!("high"));

        store
            .upsert("test", "vec-1", &embedding, metadata.clone())
            .await
            .unwrap();

        // Retrieve the vector
        let record = store.get("test", "vec-1").await.unwrap();
        assert!(record.is_some());
        let record = record.unwrap();
        assert_eq!(record.id, "vec-1");
        assert_eq!(record.metadata.get("type"), Some(&json!("incident")));

        // Search
        let results = store.search("test", &embedding, 5, None).await.unwrap();
        assert!(!results.is_empty());
        assert_eq!(results[0].id, "vec-1");

        // Delete
        store.delete("test", "vec-1").await.unwrap();
        let record = store.get("test", "vec-1").await.unwrap();
        assert!(record.is_none());
    }

    #[tokio::test]
    async fn test_mock_vector_store_search_with_filter() {
        let store = MockVectorStore::new();

        let config = CollectionConfig {
            dimension: 4,
            distance: DistanceMetric::Cosine,
            on_disk: false,
        };
        store.create_collection("test", config).await.unwrap();

        // Add vectors with different metadata
        let embedding = vec![1.0, 0.0, 0.0, 0.0];

        store
            .upsert(
                "test",
                "high-1",
                &embedding,
                VectorMetadata::new().with_field("severity", json!("high")),
            )
            .await
            .unwrap();

        store
            .upsert(
                "test",
                "low-1",
                &embedding,
                VectorMetadata::new().with_field("severity", json!("low")),
            )
            .await
            .unwrap();

        // Search with filter
        let filter = SearchFilter::Equals {
            field: "severity".to_string(),
            value: json!("high"),
        };

        let results = store
            .search("test", &embedding, 10, Some(filter))
            .await
            .unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "high-1");
    }
}
