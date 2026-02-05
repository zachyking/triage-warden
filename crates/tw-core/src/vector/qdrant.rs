//! Qdrant vector database implementation.
//!
//! Provides a production-ready vector store using Qdrant, an open-source
//! vector similarity search engine.
//!
//! # Configuration
//!
//! ```ignore
//! use tw_core::vector::{QdrantConfig, QdrantVectorStore};
//!
//! let config = QdrantConfig::new("http://localhost:6334")
//!     .with_api_key("your-api-key");
//!
//! let store = QdrantVectorStore::new(config).await?;
//! ```

use async_trait::async_trait;
use qdrant_client::qdrant::{
    condition::ConditionOneOf, r#match::MatchValue, Condition, CreateCollectionBuilder,
    DeletePointsBuilder, Distance, FieldCondition, Filter, Match, PointId, PointStruct, Range,
    ScrollPointsBuilder, SearchParams, SearchPointsBuilder, UpsertPointsBuilder,
    Value as QdrantValue, VectorParamsBuilder, VectorsConfig,
};
use qdrant_client::Qdrant;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use tracing::{debug, error, info, instrument};

use super::{
    CollectionConfig, CollectionInfo, DistanceMetric, SearchFilter, SearchResult, VectorMetadata,
    VectorRecord, VectorStore, VectorStoreError, VectorStoreResult,
};

/// Configuration for Qdrant connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QdrantConfig {
    /// Qdrant server URL (e.g., "http://localhost:6334").
    pub url: String,
    /// Optional API key for authentication.
    #[serde(default)]
    pub api_key: Option<String>,
    /// Connection timeout in seconds.
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    /// Whether to use TLS.
    #[serde(default)]
    pub use_tls: bool,
}

fn default_timeout() -> u64 {
    30
}

impl QdrantConfig {
    /// Create a new Qdrant configuration.
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            api_key: None,
            timeout_secs: default_timeout(),
            use_tls: false,
        }
    }

    /// Set the API key for authentication.
    pub fn with_api_key(mut self, api_key: impl Into<String>) -> Self {
        self.api_key = Some(api_key.into());
        self
    }

    /// Set the connection timeout.
    pub fn with_timeout(mut self, timeout_secs: u64) -> Self {
        self.timeout_secs = timeout_secs;
        self
    }

    /// Enable TLS.
    pub fn with_tls(mut self) -> Self {
        self.use_tls = true;
        self
    }

    /// Create from environment variables.
    ///
    /// Reads:
    /// - `QDRANT_URL` (required)
    /// - `QDRANT_API_KEY` (optional)
    /// - `QDRANT_TIMEOUT_SECS` (optional, default 30)
    pub fn from_env() -> Result<Self, VectorStoreError> {
        let url = std::env::var("QDRANT_URL").map_err(|_| {
            VectorStoreError::Configuration("QDRANT_URL environment variable not set".into())
        })?;

        let api_key = std::env::var("QDRANT_API_KEY").ok();
        let timeout_secs = std::env::var("QDRANT_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(default_timeout());

        Ok(Self {
            url,
            api_key,
            timeout_secs,
            use_tls: false,
        })
    }
}

/// Qdrant vector store implementation.
pub struct QdrantVectorStore {
    client: Qdrant,
    config: QdrantConfig,
}

impl QdrantVectorStore {
    /// Create a new Qdrant vector store.
    pub async fn new(config: QdrantConfig) -> VectorStoreResult<Self> {
        let mut builder = Qdrant::from_url(&config.url);

        if let Some(ref api_key) = config.api_key {
            builder = builder.api_key(api_key.clone());
        }

        let client = builder
            .timeout(std::time::Duration::from_secs(config.timeout_secs))
            .build()
            .map_err(|e| VectorStoreError::Connection(e.to_string()))?;

        info!(url = %config.url, "Connected to Qdrant");

        Ok(Self { client, config })
    }

    /// Get the configuration.
    pub fn config(&self) -> &QdrantConfig {
        &self.config
    }

    /// Convert distance metric to Qdrant's Distance enum.
    fn to_qdrant_distance(metric: DistanceMetric) -> Distance {
        match metric {
            DistanceMetric::Cosine => Distance::Cosine,
            DistanceMetric::Euclid => Distance::Euclid,
            DistanceMetric::Dot => Distance::Dot,
        }
    }

    /// Convert Qdrant's Distance to our DistanceMetric.
    fn from_qdrant_distance(distance: i32) -> DistanceMetric {
        match Distance::try_from(distance) {
            Ok(Distance::Cosine) => DistanceMetric::Cosine,
            Ok(Distance::Euclid) => DistanceMetric::Euclid,
            Ok(Distance::Dot) => DistanceMetric::Dot,
            Ok(Distance::Manhattan) => DistanceMetric::Euclid, // Approximate
            _ => DistanceMetric::Cosine,                       // Default
        }
    }

    /// Convert metadata to Qdrant payload.
    fn metadata_to_payload(metadata: &VectorMetadata) -> HashMap<String, QdrantValue> {
        metadata
            .fields
            .iter()
            .map(|(k, v)| (k.clone(), Self::json_to_qdrant_value(v)))
            .collect()
    }

    /// Convert JSON value to Qdrant value.
    fn json_to_qdrant_value(value: &Value) -> QdrantValue {
        match value {
            Value::Null => QdrantValue {
                kind: Some(qdrant_client::qdrant::value::Kind::NullValue(0)),
            },
            Value::Bool(b) => QdrantValue {
                kind: Some(qdrant_client::qdrant::value::Kind::BoolValue(*b)),
            },
            Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    QdrantValue {
                        kind: Some(qdrant_client::qdrant::value::Kind::IntegerValue(i)),
                    }
                } else if let Some(f) = n.as_f64() {
                    QdrantValue {
                        kind: Some(qdrant_client::qdrant::value::Kind::DoubleValue(f)),
                    }
                } else {
                    QdrantValue {
                        kind: Some(qdrant_client::qdrant::value::Kind::StringValue(
                            n.to_string(),
                        )),
                    }
                }
            }
            Value::String(s) => QdrantValue {
                kind: Some(qdrant_client::qdrant::value::Kind::StringValue(s.clone())),
            },
            Value::Array(arr) => {
                let list_value = qdrant_client::qdrant::ListValue {
                    values: arr.iter().map(Self::json_to_qdrant_value).collect(),
                };
                QdrantValue {
                    kind: Some(qdrant_client::qdrant::value::Kind::ListValue(list_value)),
                }
            }
            Value::Object(obj) => {
                let struct_value = qdrant_client::qdrant::Struct {
                    fields: obj
                        .iter()
                        .map(|(k, v)| (k.clone(), Self::json_to_qdrant_value(v)))
                        .collect(),
                };
                QdrantValue {
                    kind: Some(qdrant_client::qdrant::value::Kind::StructValue(
                        struct_value,
                    )),
                }
            }
        }
    }

    /// Convert Qdrant value to JSON value.
    fn qdrant_value_to_json(value: &QdrantValue) -> Value {
        match &value.kind {
            Some(qdrant_client::qdrant::value::Kind::NullValue(_)) => Value::Null,
            Some(qdrant_client::qdrant::value::Kind::BoolValue(b)) => Value::Bool(*b),
            Some(qdrant_client::qdrant::value::Kind::IntegerValue(i)) => Value::Number((*i).into()),
            Some(qdrant_client::qdrant::value::Kind::DoubleValue(f)) => {
                serde_json::Number::from_f64(*f)
                    .map(Value::Number)
                    .unwrap_or(Value::Null)
            }
            Some(qdrant_client::qdrant::value::Kind::StringValue(s)) => Value::String(s.clone()),
            Some(qdrant_client::qdrant::value::Kind::ListValue(list)) => {
                Value::Array(list.values.iter().map(Self::qdrant_value_to_json).collect())
            }
            Some(qdrant_client::qdrant::value::Kind::StructValue(s)) => Value::Object(
                s.fields
                    .iter()
                    .map(|(k, v)| (k.clone(), Self::qdrant_value_to_json(v)))
                    .collect(),
            ),
            None => Value::Null,
        }
    }

    /// Convert Qdrant payload to metadata.
    fn payload_to_metadata(payload: &HashMap<String, QdrantValue>) -> VectorMetadata {
        let fields = payload
            .iter()
            .map(|(k, v)| (k.clone(), Self::qdrant_value_to_json(v)))
            .collect();
        VectorMetadata { fields }
    }

    /// Convert SearchFilter to Qdrant Filter.
    fn search_filter_to_qdrant(filter: &SearchFilter) -> Filter {
        match filter {
            SearchFilter::Equals { field, value } => {
                let condition = Self::create_match_condition(field, value);
                Filter {
                    must: vec![condition],
                    should: vec![],
                    must_not: vec![],
                    min_should: None,
                }
            }
            SearchFilter::In { field, values } => {
                // Create OR conditions for each value
                let conditions: Vec<Condition> = values
                    .iter()
                    .map(|v| Self::create_match_condition(field, v))
                    .collect();
                Filter {
                    must: vec![],
                    should: conditions,
                    must_not: vec![],
                    min_should: Some(qdrant_client::qdrant::MinShould {
                        conditions: vec![],
                        min_count: 1,
                    }),
                }
            }
            SearchFilter::GreaterThan { field, value } => Filter {
                must: vec![Condition {
                    condition_one_of: Some(ConditionOneOf::Field(FieldCondition {
                        key: field.clone(),
                        r#match: None,
                        range: Some(Range {
                            lt: None,
                            gt: Some(*value),
                            gte: None,
                            lte: None,
                        }),
                        geo_bounding_box: None,
                        geo_radius: None,
                        values_count: None,
                        geo_polygon: None,
                        datetime_range: None,
                        is_empty: None,
                        is_null: None,
                    })),
                }],
                should: vec![],
                must_not: vec![],
                min_should: None,
            },
            SearchFilter::LessThan { field, value } => Filter {
                must: vec![Condition {
                    condition_one_of: Some(ConditionOneOf::Field(FieldCondition {
                        key: field.clone(),
                        r#match: None,
                        range: Some(Range {
                            lt: Some(*value),
                            gt: None,
                            gte: None,
                            lte: None,
                        }),
                        geo_bounding_box: None,
                        geo_radius: None,
                        values_count: None,
                        geo_polygon: None,
                        datetime_range: None,
                        is_empty: None,
                        is_null: None,
                    })),
                }],
                should: vec![],
                must_not: vec![],
                min_should: None,
            },
            SearchFilter::Range { field, min, max } => Filter {
                must: vec![Condition {
                    condition_one_of: Some(ConditionOneOf::Field(FieldCondition {
                        key: field.clone(),
                        r#match: None,
                        range: Some(Range {
                            lt: None,
                            gt: None,
                            gte: Some(*min),
                            lte: Some(*max),
                        }),
                        geo_bounding_box: None,
                        geo_radius: None,
                        values_count: None,
                        geo_polygon: None,
                        datetime_range: None,
                        is_empty: None,
                        is_null: None,
                    })),
                }],
                should: vec![],
                must_not: vec![],
                min_should: None,
            },
            SearchFilter::And(filters) => {
                let must: Vec<Condition> = filters
                    .iter()
                    .map(|f| Condition {
                        condition_one_of: Some(ConditionOneOf::Filter(
                            Self::search_filter_to_qdrant(f),
                        )),
                    })
                    .collect();
                Filter {
                    must,
                    should: vec![],
                    must_not: vec![],
                    min_should: None,
                }
            }
            SearchFilter::Or(filters) => {
                let should: Vec<Condition> = filters
                    .iter()
                    .map(|f| Condition {
                        condition_one_of: Some(ConditionOneOf::Filter(
                            Self::search_filter_to_qdrant(f),
                        )),
                    })
                    .collect();
                Filter {
                    must: vec![],
                    should,
                    must_not: vec![],
                    min_should: Some(qdrant_client::qdrant::MinShould {
                        conditions: vec![],
                        min_count: 1,
                    }),
                }
            }
            SearchFilter::Not(filter) => {
                let inner = Self::search_filter_to_qdrant(filter);
                Filter {
                    must: vec![],
                    should: vec![],
                    must_not: vec![Condition {
                        condition_one_of: Some(ConditionOneOf::Filter(inner)),
                    }],
                    min_should: None,
                }
            }
        }
    }

    /// Create a match condition for a field/value pair.
    fn create_match_condition(field: &str, value: &Value) -> Condition {
        let match_value = match value {
            Value::String(s) => Some(MatchValue::Keyword(s.clone())),
            Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    Some(MatchValue::Integer(i))
                } else {
                    // Float matching - convert to string
                    Some(MatchValue::Keyword(n.to_string()))
                }
            }
            Value::Bool(b) => Some(MatchValue::Boolean(*b)),
            _ => None,
        };

        Condition {
            condition_one_of: match_value.map(|mv| {
                ConditionOneOf::Field(FieldCondition {
                    key: field.to_string(),
                    r#match: Some(Match {
                        match_value: Some(mv),
                    }),
                    range: None,
                    geo_bounding_box: None,
                    geo_radius: None,
                    values_count: None,
                    geo_polygon: None,
                    datetime_range: None,
                    is_empty: None,
                    is_null: None,
                })
            }),
        }
    }
}

#[async_trait]
impl VectorStore for QdrantVectorStore {
    #[instrument(skip(self), fields(collection = %name))]
    async fn create_collection(
        &self,
        name: &str,
        config: CollectionConfig,
    ) -> VectorStoreResult<()> {
        // Check if collection already exists
        let exists = self
            .client
            .collection_exists(name)
            .await
            .map_err(|e| VectorStoreError::Internal(e.to_string()))?;

        if exists {
            return Err(VectorStoreError::CollectionExists(name.to_string()));
        }

        let distance = Self::to_qdrant_distance(config.distance);

        let vectors_config = VectorsConfig {
            config: Some(qdrant_client::qdrant::vectors_config::Config::Params(
                VectorParamsBuilder::new(config.dimension as u64, distance)
                    .on_disk(config.on_disk)
                    .build(),
            )),
        };

        let create_collection = CreateCollectionBuilder::new(name).vectors_config(vectors_config);

        self.client
            .create_collection(create_collection)
            .await
            .map_err(|e| VectorStoreError::Internal(e.to_string()))?;

        info!(collection = %name, dimension = config.dimension, "Created Qdrant collection");

        Ok(())
    }

    #[instrument(skip(self), fields(collection = %name))]
    async fn delete_collection(&self, name: &str) -> VectorStoreResult<()> {
        // Check if collection exists
        let exists = self
            .client
            .collection_exists(name)
            .await
            .map_err(|e| VectorStoreError::Internal(e.to_string()))?;

        if !exists {
            return Err(VectorStoreError::CollectionNotFound(name.to_string()));
        }

        self.client
            .delete_collection(name)
            .await
            .map_err(|e| VectorStoreError::Internal(e.to_string()))?;

        info!(collection = %name, "Deleted Qdrant collection");

        Ok(())
    }

    #[instrument(skip(self), fields(collection = %name))]
    async fn collection_info(&self, name: &str) -> VectorStoreResult<CollectionInfo> {
        let info = self.client.collection_info(name).await.map_err(|e| {
            if e.to_string().contains("not found") {
                VectorStoreError::CollectionNotFound(name.to_string())
            } else {
                VectorStoreError::Internal(e.to_string())
            }
        })?;

        let result = info
            .result
            .ok_or_else(|| VectorStoreError::Internal("No collection info returned".to_string()))?;

        // Extract vector params
        let vectors_config = result
            .config
            .and_then(|c| c.params)
            .and_then(|p| p.vectors_config);

        let (dimension, distance, on_disk) = match vectors_config {
            Some(VectorsConfig {
                config: Some(qdrant_client::qdrant::vectors_config::Config::Params(params)),
            }) => (
                params.size as usize,
                Self::from_qdrant_distance(params.distance),
                params.on_disk.unwrap_or(false),
            ),
            _ => (0, DistanceMetric::Cosine, false),
        };

        Ok(CollectionInfo {
            name: name.to_string(),
            vectors_count: result.points_count.unwrap_or(0),
            dimension,
            distance,
            on_disk,
        })
    }

    async fn collection_exists(&self, name: &str) -> VectorStoreResult<bool> {
        self.client
            .collection_exists(name)
            .await
            .map_err(|e| VectorStoreError::Internal(e.to_string()))
    }

    #[instrument(skip(self, embedding, metadata), fields(collection = %collection, id = %id))]
    async fn upsert(
        &self,
        collection: &str,
        id: &str,
        embedding: &[f32],
        metadata: VectorMetadata,
    ) -> VectorStoreResult<()> {
        let payload = Self::metadata_to_payload(&metadata);

        let point = PointStruct::new(id.to_string(), embedding.to_vec(), payload);

        self.client
            .upsert_points(UpsertPointsBuilder::new(collection, vec![point]).wait(true))
            .await
            .map_err(|e| {
                if e.to_string().contains("not found") {
                    VectorStoreError::CollectionNotFound(collection.to_string())
                } else {
                    VectorStoreError::Internal(e.to_string())
                }
            })?;

        debug!(collection = %collection, id = %id, "Upserted vector");

        Ok(())
    }

    #[instrument(skip(self, records), fields(collection = %collection, count = records.len()))]
    async fn upsert_batch(
        &self,
        collection: &str,
        records: Vec<VectorRecord>,
    ) -> VectorStoreResult<()> {
        if records.is_empty() {
            return Ok(());
        }

        let points: Vec<PointStruct> = records
            .into_iter()
            .map(|r| {
                let payload = Self::metadata_to_payload(&r.metadata);
                PointStruct::new(r.id, r.embedding, payload)
            })
            .collect();

        let count = points.len();

        self.client
            .upsert_points(UpsertPointsBuilder::new(collection, points).wait(true))
            .await
            .map_err(|e| {
                if e.to_string().contains("not found") {
                    VectorStoreError::CollectionNotFound(collection.to_string())
                } else {
                    VectorStoreError::Internal(e.to_string())
                }
            })?;

        debug!(collection = %collection, count = count, "Upserted batch");

        Ok(())
    }

    #[instrument(skip(self, embedding, filter), fields(collection = %collection, top_k = top_k))]
    async fn search(
        &self,
        collection: &str,
        embedding: &[f32],
        top_k: usize,
        filter: Option<SearchFilter>,
    ) -> VectorStoreResult<Vec<SearchResult>> {
        let mut search = SearchPointsBuilder::new(collection, embedding.to_vec(), top_k as u64)
            .with_payload(true)
            .params(SearchParams::default());

        if let Some(ref f) = filter {
            search = search.filter(Self::search_filter_to_qdrant(f));
        }

        let response = self.client.search_points(search).await.map_err(|e| {
            if e.to_string().contains("not found") {
                VectorStoreError::CollectionNotFound(collection.to_string())
            } else {
                VectorStoreError::Internal(e.to_string())
            }
        })?;

        let results = response
            .result
            .into_iter()
            .filter_map(|point| {
                let id = match point.id? {
                    PointId {
                        point_id_options:
                            Some(qdrant_client::qdrant::point_id::PointIdOptions::Uuid(uuid)),
                    } => uuid,
                    PointId {
                        point_id_options:
                            Some(qdrant_client::qdrant::point_id::PointIdOptions::Num(num)),
                    } => num.to_string(),
                    _ => return None,
                };

                let metadata = Self::payload_to_metadata(&point.payload);
                let score = point.score;

                Some(SearchResult::new(id, score, metadata))
            })
            .collect();

        Ok(results)
    }

    #[instrument(skip(self), fields(collection = %collection, id = %id))]
    async fn delete(&self, collection: &str, id: &str) -> VectorStoreResult<()> {
        let point_ids = vec![id.to_string()];
        let delete_request = DeletePointsBuilder::new(collection)
            .points(point_ids)
            .wait(true);

        self.client
            .delete_points(delete_request)
            .await
            .map_err(|e| {
                if e.to_string().contains("not found") {
                    VectorStoreError::CollectionNotFound(collection.to_string())
                } else {
                    VectorStoreError::Internal(e.to_string())
                }
            })?;

        debug!(collection = %collection, id = %id, "Deleted vector");

        Ok(())
    }

    #[instrument(skip(self, ids), fields(collection = %collection, count = ids.len()))]
    async fn delete_batch(&self, collection: &str, ids: &[&str]) -> VectorStoreResult<()> {
        if ids.is_empty() {
            return Ok(());
        }

        let point_ids: Vec<String> = ids.iter().map(|id| id.to_string()).collect();
        let delete_request = DeletePointsBuilder::new(collection)
            .points(point_ids)
            .wait(true);

        self.client
            .delete_points(delete_request)
            .await
            .map_err(|e| {
                if e.to_string().contains("not found") {
                    VectorStoreError::CollectionNotFound(collection.to_string())
                } else {
                    VectorStoreError::Internal(e.to_string())
                }
            })?;

        debug!(collection = %collection, count = ids.len(), "Deleted batch");

        Ok(())
    }

    #[instrument(skip(self), fields(collection = %collection, id = %id))]
    async fn get(&self, collection: &str, id: &str) -> VectorStoreResult<Option<VectorRecord>> {
        let scroll = ScrollPointsBuilder::new(collection)
            .filter(Filter {
                must: vec![Condition {
                    condition_one_of: Some(ConditionOneOf::HasId(
                        qdrant_client::qdrant::HasIdCondition {
                            has_id: vec![PointId {
                                point_id_options: Some(
                                    qdrant_client::qdrant::point_id::PointIdOptions::Uuid(
                                        id.to_string(),
                                    ),
                                ),
                            }],
                        },
                    )),
                }],
                should: vec![],
                must_not: vec![],
                min_should: None,
            })
            .with_payload(true)
            .with_vectors(true)
            .limit(1);

        let response = self.client.scroll(scroll).await.map_err(|e| {
            if e.to_string().contains("not found") {
                VectorStoreError::CollectionNotFound(collection.to_string())
            } else {
                VectorStoreError::Internal(e.to_string())
            }
        })?;

        let record = response.result.into_iter().next().and_then(|point| {
            let point_id = match point.id? {
                PointId {
                    point_id_options:
                        Some(qdrant_client::qdrant::point_id::PointIdOptions::Uuid(uuid)),
                } => uuid,
                PointId {
                    point_id_options:
                        Some(qdrant_client::qdrant::point_id::PointIdOptions::Num(num)),
                } => num.to_string(),
                _ => return None,
            };

            let metadata = Self::payload_to_metadata(&point.payload);

            // Extract vector
            #[allow(deprecated)]
            let embedding = match point.vectors?.vectors_options? {
                qdrant_client::qdrant::vectors_output::VectorsOptions::Vector(v) => v.data,
                _ => return None,
            };

            Some(VectorRecord {
                id: point_id,
                embedding,
                metadata,
            })
        });

        Ok(record)
    }

    async fn health_check(&self) -> bool {
        match self.client.health_check().await {
            Ok(_) => true,
            Err(e) => {
                error!(error = %e, "Qdrant health check failed");
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_builder() {
        let config = QdrantConfig::new("http://localhost:6334")
            .with_api_key("test-key")
            .with_timeout(60)
            .with_tls();

        assert_eq!(config.url, "http://localhost:6334");
        assert_eq!(config.api_key, Some("test-key".to_string()));
        assert_eq!(config.timeout_secs, 60);
        assert!(config.use_tls);
    }

    #[test]
    fn test_distance_conversion() {
        assert_eq!(
            QdrantVectorStore::to_qdrant_distance(DistanceMetric::Cosine),
            Distance::Cosine
        );
        assert_eq!(
            QdrantVectorStore::to_qdrant_distance(DistanceMetric::Euclid),
            Distance::Euclid
        );
        assert_eq!(
            QdrantVectorStore::to_qdrant_distance(DistanceMetric::Dot),
            Distance::Dot
        );
    }

    #[test]
    fn test_json_to_qdrant_value() {
        use serde_json::json;

        // String
        let v = QdrantVectorStore::json_to_qdrant_value(&json!("test"));
        assert!(matches!(
            v.kind,
            Some(qdrant_client::qdrant::value::Kind::StringValue(_))
        ));

        // Integer
        let v = QdrantVectorStore::json_to_qdrant_value(&json!(42));
        assert!(matches!(
            v.kind,
            Some(qdrant_client::qdrant::value::Kind::IntegerValue(42))
        ));

        // Float
        let v = QdrantVectorStore::json_to_qdrant_value(&json!(3.14));
        assert!(matches!(
            v.kind,
            Some(qdrant_client::qdrant::value::Kind::DoubleValue(_))
        ));

        // Boolean
        let v = QdrantVectorStore::json_to_qdrant_value(&json!(true));
        assert!(matches!(
            v.kind,
            Some(qdrant_client::qdrant::value::Kind::BoolValue(true))
        ));
    }
}
