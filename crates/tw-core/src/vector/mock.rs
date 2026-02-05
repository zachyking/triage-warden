//! Mock vector store for testing.
//!
//! Provides an in-memory implementation of the VectorStore trait
//! for use in unit tests without requiring a real vector database.

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::RwLock;

use super::{
    CollectionConfig, CollectionInfo, DistanceMetric, SearchFilter, SearchResult, VectorMetadata,
    VectorRecord, VectorStore, VectorStoreError, VectorStoreResult,
};

/// In-memory mock vector store for testing.
///
/// Thread-safe and suitable for concurrent test execution.
/// Implements basic similarity search using cosine similarity.
#[derive(Debug)]
pub struct MockVectorStore {
    /// Collections with their configurations.
    collections: RwLock<HashMap<String, CollectionData>>,
    /// Simulated health status.
    healthy: RwLock<bool>,
}

#[derive(Debug, Clone)]
struct CollectionData {
    config: CollectionConfig,
    vectors: HashMap<String, VectorRecord>,
}

impl Default for MockVectorStore {
    fn default() -> Self {
        Self::new()
    }
}

impl MockVectorStore {
    /// Create a new mock vector store.
    pub fn new() -> Self {
        Self {
            collections: RwLock::new(HashMap::new()),
            healthy: RwLock::new(true),
        }
    }

    /// Set the health status for testing health check behavior.
    pub fn set_healthy(&self, healthy: bool) {
        *self.healthy.write().unwrap() = healthy;
    }

    /// Get the number of collections.
    pub fn collection_count(&self) -> usize {
        self.collections.read().unwrap().len()
    }

    /// Calculate cosine similarity between two vectors.
    fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
        if a.len() != b.len() {
            return 0.0;
        }

        let dot: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
        let norm_a: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
        let norm_b: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();

        if norm_a == 0.0 || norm_b == 0.0 {
            0.0
        } else {
            dot / (norm_a * norm_b)
        }
    }

    /// Calculate euclidean distance between two vectors.
    fn euclidean_distance(a: &[f32], b: &[f32]) -> f32 {
        if a.len() != b.len() {
            return f32::MAX;
        }

        a.iter()
            .zip(b.iter())
            .map(|(x, y)| (x - y).powi(2))
            .sum::<f32>()
            .sqrt()
    }

    /// Calculate dot product between two vectors.
    fn dot_product(a: &[f32], b: &[f32]) -> f32 {
        if a.len() != b.len() {
            return 0.0;
        }

        a.iter().zip(b.iter()).map(|(x, y)| x * y).sum()
    }

    /// Calculate similarity score based on distance metric.
    fn calculate_score(a: &[f32], b: &[f32], metric: DistanceMetric) -> f32 {
        match metric {
            DistanceMetric::Cosine => Self::cosine_similarity(a, b),
            DistanceMetric::Euclid => {
                // Convert distance to similarity (lower distance = higher similarity)
                let distance = Self::euclidean_distance(a, b);
                1.0 / (1.0 + distance)
            }
            DistanceMetric::Dot => Self::dot_product(a, b),
        }
    }
}

#[async_trait]
impl VectorStore for MockVectorStore {
    async fn create_collection(
        &self,
        name: &str,
        config: CollectionConfig,
    ) -> VectorStoreResult<()> {
        let mut collections = self.collections.write().unwrap();

        if collections.contains_key(name) {
            return Err(VectorStoreError::CollectionExists(name.to_string()));
        }

        collections.insert(
            name.to_string(),
            CollectionData {
                config,
                vectors: HashMap::new(),
            },
        );

        Ok(())
    }

    async fn delete_collection(&self, name: &str) -> VectorStoreResult<()> {
        let mut collections = self.collections.write().unwrap();

        if collections.remove(name).is_none() {
            return Err(VectorStoreError::CollectionNotFound(name.to_string()));
        }

        Ok(())
    }

    async fn collection_info(&self, name: &str) -> VectorStoreResult<CollectionInfo> {
        let collections = self.collections.read().unwrap();

        let data = collections
            .get(name)
            .ok_or_else(|| VectorStoreError::CollectionNotFound(name.to_string()))?;

        Ok(CollectionInfo {
            name: name.to_string(),
            vectors_count: data.vectors.len() as u64,
            dimension: data.config.dimension,
            distance: data.config.distance,
            on_disk: data.config.on_disk,
        })
    }

    async fn collection_exists(&self, name: &str) -> VectorStoreResult<bool> {
        Ok(self.collections.read().unwrap().contains_key(name))
    }

    async fn upsert(
        &self,
        collection: &str,
        id: &str,
        embedding: &[f32],
        metadata: VectorMetadata,
    ) -> VectorStoreResult<()> {
        let mut collections = self.collections.write().unwrap();

        let data = collections
            .get_mut(collection)
            .ok_or_else(|| VectorStoreError::CollectionNotFound(collection.to_string()))?;

        // Validate dimension
        if embedding.len() != data.config.dimension {
            return Err(VectorStoreError::DimensionMismatch {
                expected: data.config.dimension,
                actual: embedding.len(),
            });
        }

        data.vectors.insert(
            id.to_string(),
            VectorRecord {
                id: id.to_string(),
                embedding: embedding.to_vec(),
                metadata,
            },
        );

        Ok(())
    }

    async fn upsert_batch(
        &self,
        collection: &str,
        records: Vec<VectorRecord>,
    ) -> VectorStoreResult<()> {
        let mut collections = self.collections.write().unwrap();

        let data = collections
            .get_mut(collection)
            .ok_or_else(|| VectorStoreError::CollectionNotFound(collection.to_string()))?;

        let mut errors = Vec::new();
        let total = records.len();

        for record in records {
            if record.embedding.len() != data.config.dimension {
                errors.push(format!(
                    "Vector '{}': dimension mismatch (expected {}, got {})",
                    record.id,
                    data.config.dimension,
                    record.embedding.len()
                ));
                continue;
            }
            data.vectors.insert(record.id.clone(), record);
        }

        if !errors.is_empty() {
            return Err(VectorStoreError::PartialBatchFailure {
                failed_count: errors.len(),
                total_count: total,
                errors,
            });
        }

        Ok(())
    }

    async fn search(
        &self,
        collection: &str,
        embedding: &[f32],
        top_k: usize,
        filter: Option<SearchFilter>,
    ) -> VectorStoreResult<Vec<SearchResult>> {
        let collections = self.collections.read().unwrap();

        let data = collections
            .get(collection)
            .ok_or_else(|| VectorStoreError::CollectionNotFound(collection.to_string()))?;

        // Calculate scores for all vectors
        let mut results: Vec<SearchResult> = data
            .vectors
            .values()
            .filter(|record| {
                // Apply filter if provided
                filter
                    .as_ref()
                    .map(|f| f.matches(&record.metadata))
                    .unwrap_or(true)
            })
            .map(|record| {
                let score =
                    Self::calculate_score(embedding, &record.embedding, data.config.distance);
                SearchResult::new(record.id.clone(), score, record.metadata.clone())
            })
            .collect();

        // Sort by score (descending for cosine/dot, ascending for euclidean converted)
        results.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        // Take top_k
        results.truncate(top_k);

        Ok(results)
    }

    async fn delete(&self, collection: &str, id: &str) -> VectorStoreResult<()> {
        let mut collections = self.collections.write().unwrap();

        let data = collections
            .get_mut(collection)
            .ok_or_else(|| VectorStoreError::CollectionNotFound(collection.to_string()))?;

        // Deleting non-existent is not an error
        data.vectors.remove(id);

        Ok(())
    }

    async fn delete_batch(&self, collection: &str, ids: &[&str]) -> VectorStoreResult<()> {
        let mut collections = self.collections.write().unwrap();

        let data = collections
            .get_mut(collection)
            .ok_or_else(|| VectorStoreError::CollectionNotFound(collection.to_string()))?;

        for id in ids {
            data.vectors.remove(*id);
        }

        Ok(())
    }

    async fn get(&self, collection: &str, id: &str) -> VectorStoreResult<Option<VectorRecord>> {
        let collections = self.collections.read().unwrap();

        let data = collections
            .get(collection)
            .ok_or_else(|| VectorStoreError::CollectionNotFound(collection.to_string()))?;

        Ok(data.vectors.get(id).cloned())
    }

    async fn health_check(&self) -> bool {
        *self.healthy.read().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn test_create_and_delete_collection() {
        let store = MockVectorStore::new();

        // Create collection
        let config = CollectionConfig::new(384).with_cosine();
        store
            .create_collection("test", config.clone())
            .await
            .unwrap();

        // Verify exists
        assert!(store.collection_exists("test").await.unwrap());

        // Cannot create duplicate
        let err = store.create_collection("test", config).await.unwrap_err();
        assert!(matches!(err, VectorStoreError::CollectionExists(_)));

        // Delete
        store.delete_collection("test").await.unwrap();
        assert!(!store.collection_exists("test").await.unwrap());

        // Cannot delete non-existent
        let err = store.delete_collection("test").await.unwrap_err();
        assert!(matches!(err, VectorStoreError::CollectionNotFound(_)));
    }

    #[tokio::test]
    async fn test_upsert_and_get() {
        let store = MockVectorStore::new();
        let config = CollectionConfig::new(4);
        store.create_collection("test", config).await.unwrap();

        let embedding = vec![1.0, 0.0, 0.0, 0.0];
        let metadata = VectorMetadata::new().with_field("type", json!("test"));

        // Upsert
        store
            .upsert("test", "vec-1", &embedding, metadata)
            .await
            .unwrap();

        // Get
        let record = store.get("test", "vec-1").await.unwrap().unwrap();
        assert_eq!(record.id, "vec-1");
        assert_eq!(record.embedding, embedding);
        assert_eq!(record.metadata.get_str("type"), Some("test"));

        // Update (upsert existing)
        let new_metadata = VectorMetadata::new().with_field("type", json!("updated"));
        store
            .upsert("test", "vec-1", &embedding, new_metadata)
            .await
            .unwrap();

        let record = store.get("test", "vec-1").await.unwrap().unwrap();
        assert_eq!(record.metadata.get_str("type"), Some("updated"));
    }

    #[tokio::test]
    async fn test_dimension_validation() {
        let store = MockVectorStore::new();
        let config = CollectionConfig::new(4);
        store.create_collection("test", config).await.unwrap();

        // Wrong dimension
        let embedding = vec![1.0, 0.0, 0.0]; // 3 instead of 4
        let err = store
            .upsert("test", "vec-1", &embedding, VectorMetadata::new())
            .await
            .unwrap_err();

        assert!(matches!(err, VectorStoreError::DimensionMismatch { .. }));
    }

    #[tokio::test]
    async fn test_cosine_search() {
        let store = MockVectorStore::new();
        let config = CollectionConfig::new(4).with_cosine();
        store.create_collection("test", config).await.unwrap();

        // Add orthogonal vectors
        store
            .upsert(
                "test",
                "x",
                &[1.0, 0.0, 0.0, 0.0],
                VectorMetadata::new().with_field("name", json!("x")),
            )
            .await
            .unwrap();

        store
            .upsert(
                "test",
                "y",
                &[0.0, 1.0, 0.0, 0.0],
                VectorMetadata::new().with_field("name", json!("y")),
            )
            .await
            .unwrap();

        store
            .upsert(
                "test",
                "similar_to_x",
                &[0.9, 0.1, 0.0, 0.0],
                VectorMetadata::new().with_field("name", json!("similar_to_x")),
            )
            .await
            .unwrap();

        // Search for vectors similar to x
        let query = vec![1.0, 0.0, 0.0, 0.0];
        let results = store.search("test", &query, 3, None).await.unwrap();

        // x should be most similar (score = 1.0)
        assert_eq!(results[0].id, "x");
        assert!((results[0].score - 1.0).abs() < 0.001);

        // similar_to_x should be second
        assert_eq!(results[1].id, "similar_to_x");

        // y should be least similar (orthogonal, score = 0.0)
        assert_eq!(results[2].id, "y");
        assert!(results[2].score.abs() < 0.001);
    }

    #[tokio::test]
    async fn test_health_check() {
        let store = MockVectorStore::new();

        assert!(store.health_check().await);

        store.set_healthy(false);
        assert!(!store.health_check().await);
    }
}
