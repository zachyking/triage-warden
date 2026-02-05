//! Vector store types and data structures.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

/// Distance metric for vector similarity search.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DistanceMetric {
    /// Cosine similarity (default, best for normalized embeddings).
    #[default]
    Cosine,
    /// Euclidean (L2) distance.
    Euclid,
    /// Dot product (for non-normalized embeddings).
    Dot,
}

/// Configuration for creating a vector collection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectionConfig {
    /// Vector dimension (must match embedding model output).
    pub dimension: usize,
    /// Distance metric for similarity calculations.
    #[serde(default)]
    pub distance: DistanceMetric,
    /// Whether to store vectors on disk (for large collections).
    #[serde(default)]
    pub on_disk: bool,
}

impl CollectionConfig {
    /// Create a new collection config with the specified dimension.
    pub fn new(dimension: usize) -> Self {
        Self {
            dimension,
            distance: DistanceMetric::default(),
            on_disk: false,
        }
    }

    /// Use cosine distance metric.
    pub fn with_cosine(mut self) -> Self {
        self.distance = DistanceMetric::Cosine;
        self
    }

    /// Use euclidean distance metric.
    pub fn with_euclid(mut self) -> Self {
        self.distance = DistanceMetric::Euclid;
        self
    }

    /// Use dot product distance metric.
    pub fn with_dot(mut self) -> Self {
        self.distance = DistanceMetric::Dot;
        self
    }

    /// Enable on-disk storage.
    pub fn with_on_disk(mut self, on_disk: bool) -> Self {
        self.on_disk = on_disk;
        self
    }
}

/// Information about an existing collection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectionInfo {
    /// Collection name.
    pub name: String,
    /// Number of vectors in the collection.
    pub vectors_count: u64,
    /// Vector dimension.
    pub dimension: usize,
    /// Distance metric.
    pub distance: DistanceMetric,
    /// Whether vectors are stored on disk.
    pub on_disk: bool,
}

/// Metadata associated with a vector.
///
/// Stored alongside the embedding and used for filtering during search.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VectorMetadata {
    /// Metadata fields.
    #[serde(flatten)]
    pub fields: HashMap<String, Value>,
}

impl VectorMetadata {
    /// Create empty metadata.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create metadata from a JSON value.
    ///
    /// If the value is an object, its fields are used as metadata.
    /// Otherwise, the value is stored under a "value" key.
    pub fn from_value(value: Value) -> Self {
        match value {
            Value::Object(map) => Self {
                fields: map.into_iter().collect(),
            },
            other => Self {
                fields: [("value".to_string(), other)].into_iter().collect(),
            },
        }
    }

    /// Add a metadata field.
    pub fn with_field(mut self, key: impl Into<String>, value: Value) -> Self {
        self.fields.insert(key.into(), value);
        self
    }

    /// Set a metadata field.
    pub fn set(&mut self, key: impl Into<String>, value: Value) {
        self.fields.insert(key.into(), value);
    }

    /// Get a metadata field.
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.fields.get(key)
    }

    /// Check if a field exists.
    pub fn contains(&self, key: &str) -> bool {
        self.fields.contains_key(key)
    }

    /// Get a string field value.
    pub fn get_str(&self, key: &str) -> Option<&str> {
        self.fields.get(key).and_then(|v| v.as_str())
    }

    /// Get an integer field value.
    pub fn get_i64(&self, key: &str) -> Option<i64> {
        self.fields.get(key).and_then(|v| v.as_i64())
    }

    /// Get a float field value.
    pub fn get_f64(&self, key: &str) -> Option<f64> {
        self.fields.get(key).and_then(|v| v.as_f64())
    }

    /// Get a boolean field value.
    pub fn get_bool(&self, key: &str) -> Option<bool> {
        self.fields.get(key).and_then(|v| v.as_bool())
    }

    /// Convert to JSON value.
    pub fn to_value(&self) -> Value {
        Value::Object(self.fields.clone().into_iter().collect())
    }
}

impl From<Value> for VectorMetadata {
    fn from(value: Value) -> Self {
        Self::from_value(value)
    }
}

impl From<HashMap<String, Value>> for VectorMetadata {
    fn from(fields: HashMap<String, Value>) -> Self {
        Self { fields }
    }
}

/// A vector record with ID, embedding, and metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VectorRecord {
    /// Unique identifier.
    pub id: String,
    /// Vector embedding.
    pub embedding: Vec<f32>,
    /// Associated metadata.
    pub metadata: VectorMetadata,
}

impl VectorRecord {
    /// Create a new vector record.
    pub fn new(id: impl Into<String>, embedding: Vec<f32>, metadata: VectorMetadata) -> Self {
        Self {
            id: id.into(),
            embedding,
            metadata,
        }
    }
}

/// A search result with similarity score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    /// Vector ID.
    pub id: String,
    /// Similarity score (higher is more similar for cosine/dot, lower for euclidean).
    pub score: f32,
    /// Associated metadata.
    pub metadata: VectorMetadata,
    /// The vector embedding (optional, may not be included for efficiency).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub embedding: Option<Vec<f32>>,
}

impl SearchResult {
    /// Create a new search result.
    pub fn new(id: impl Into<String>, score: f32, metadata: VectorMetadata) -> Self {
        Self {
            id: id.into(),
            score,
            metadata,
            embedding: None,
        }
    }

    /// Include the embedding in the result.
    pub fn with_embedding(mut self, embedding: Vec<f32>) -> Self {
        self.embedding = Some(embedding);
        self
    }
}

/// Filter for vector search operations.
///
/// Allows filtering search results based on metadata fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SearchFilter {
    /// Exact match on a field value.
    Equals { field: String, value: Value },
    /// Match if field value is in a list.
    In { field: String, values: Vec<Value> },
    /// Match if field value is greater than.
    GreaterThan { field: String, value: f64 },
    /// Match if field value is less than.
    LessThan { field: String, value: f64 },
    /// Match if field value is in range (inclusive).
    Range { field: String, min: f64, max: f64 },
    /// Match all conditions (AND).
    And(Vec<SearchFilter>),
    /// Match any condition (OR).
    Or(Vec<SearchFilter>),
    /// Negate a condition.
    Not(Box<SearchFilter>),
}

impl SearchFilter {
    /// Create an equals filter.
    pub fn equals(field: impl Into<String>, value: impl Into<Value>) -> Self {
        Self::Equals {
            field: field.into(),
            value: value.into(),
        }
    }

    /// Create an "in" filter for matching multiple values.
    pub fn is_in(field: impl Into<String>, values: Vec<Value>) -> Self {
        Self::In {
            field: field.into(),
            values,
        }
    }

    /// Create a greater-than filter.
    pub fn gt(field: impl Into<String>, value: f64) -> Self {
        Self::GreaterThan {
            field: field.into(),
            value,
        }
    }

    /// Create a less-than filter.
    pub fn lt(field: impl Into<String>, value: f64) -> Self {
        Self::LessThan {
            field: field.into(),
            value,
        }
    }

    /// Create a range filter.
    pub fn range(field: impl Into<String>, min: f64, max: f64) -> Self {
        Self::Range {
            field: field.into(),
            min,
            max,
        }
    }

    /// Combine filters with AND.
    pub fn and(filters: Vec<SearchFilter>) -> Self {
        Self::And(filters)
    }

    /// Combine filters with OR.
    pub fn or(filters: Vec<SearchFilter>) -> Self {
        Self::Or(filters)
    }

    /// Negate a filter.
    pub fn negate(filter: SearchFilter) -> Self {
        Self::Not(Box::new(filter))
    }

    /// Check if a metadata value matches this filter.
    pub fn matches(&self, metadata: &VectorMetadata) -> bool {
        match self {
            SearchFilter::Equals { field, value } => metadata.get(field) == Some(value),
            SearchFilter::In { field, values } => metadata
                .get(field)
                .map(|v| values.contains(v))
                .unwrap_or(false),
            SearchFilter::GreaterThan { field, value } => {
                metadata.get_f64(field).map(|v| v > *value).unwrap_or(false)
            }
            SearchFilter::LessThan { field, value } => {
                metadata.get_f64(field).map(|v| v < *value).unwrap_or(false)
            }
            SearchFilter::Range { field, min, max } => metadata
                .get_f64(field)
                .map(|v| v >= *min && v <= *max)
                .unwrap_or(false),
            SearchFilter::And(filters) => filters.iter().all(|f| f.matches(metadata)),
            SearchFilter::Or(filters) => filters.iter().any(|f| f.matches(metadata)),
            SearchFilter::Not(filter) => !filter.matches(metadata),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_metadata_operations() {
        let mut meta = VectorMetadata::new()
            .with_field("type", json!("incident"))
            .with_field("severity", json!("high"))
            .with_field("score", json!(0.95));

        assert_eq!(meta.get_str("type"), Some("incident"));
        assert_eq!(meta.get_str("severity"), Some("high"));
        assert_eq!(meta.get_f64("score"), Some(0.95));
        assert!(meta.contains("type"));
        assert!(!meta.contains("nonexistent"));

        meta.set("priority", json!(1));
        assert_eq!(meta.get_i64("priority"), Some(1));
    }

    #[test]
    fn test_search_filter_matches() {
        let meta = VectorMetadata::new()
            .with_field("severity", json!("high"))
            .with_field("score", json!(0.85))
            .with_field("type", json!("incident"));

        // Equals
        assert!(SearchFilter::equals("severity", "high").matches(&meta));
        assert!(!SearchFilter::equals("severity", "low").matches(&meta));

        // In
        assert!(
            SearchFilter::is_in("severity", vec![json!("high"), json!("critical")]).matches(&meta)
        );
        assert!(
            !SearchFilter::is_in("severity", vec![json!("low"), json!("medium")]).matches(&meta)
        );

        // Greater than
        assert!(SearchFilter::gt("score", 0.5).matches(&meta));
        assert!(!SearchFilter::gt("score", 0.9).matches(&meta));

        // Less than
        assert!(SearchFilter::lt("score", 0.9).matches(&meta));
        assert!(!SearchFilter::lt("score", 0.5).matches(&meta));

        // Range
        assert!(SearchFilter::range("score", 0.8, 0.9).matches(&meta));
        assert!(!SearchFilter::range("score", 0.9, 1.0).matches(&meta));

        // And
        let and_filter = SearchFilter::and(vec![
            SearchFilter::equals("severity", "high"),
            SearchFilter::equals("type", "incident"),
        ]);
        assert!(and_filter.matches(&meta));

        // Or
        let or_filter = SearchFilter::or(vec![
            SearchFilter::equals("severity", "low"),
            SearchFilter::equals("type", "incident"),
        ]);
        assert!(or_filter.matches(&meta));

        // Not
        assert!(SearchFilter::negate(SearchFilter::equals("severity", "low")).matches(&meta));
        assert!(!SearchFilter::negate(SearchFilter::equals("severity", "high")).matches(&meta));
    }

    #[test]
    fn test_collection_config_builder() {
        let config = CollectionConfig::new(384).with_cosine().with_on_disk(true);

        assert_eq!(config.dimension, 384);
        assert_eq!(config.distance, DistanceMetric::Cosine);
        assert!(config.on_disk);
    }
}
