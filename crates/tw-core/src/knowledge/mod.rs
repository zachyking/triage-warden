//! Knowledge base document models for RAG integration.
//!
//! This module provides data models for storing and indexing organizational
//! knowledge documents such as runbooks, threat intelligence reports,
//! security policies, and vendor documentation.
//!
//! # Document Types
//!
//! The knowledge base supports several document types:
//!
//! - **Runbook**: Step-by-step procedures for incident response
//! - **ThreatIntelReport**: Threat intelligence analysis and IOCs
//! - **SecurityPolicy**: Organizational security policies
//! - **PostMortem**: Incident post-mortem analyses
//! - **VendorDocumentation**: External tool/service documentation
//!
//! # Example
//!
//! ```ignore
//! use tw_core::knowledge::{KnowledgeDocument, KnowledgeType, DocumentMetadata};
//!
//! let doc = KnowledgeDocument {
//!     id: Uuid::new_v4(),
//!     tenant_id: Uuid::new_v4(),
//!     doc_type: KnowledgeType::Runbook,
//!     title: "Phishing Response Procedure".to_string(),
//!     content: "## Overview\n\nThis runbook covers...".to_string(),
//!     metadata: DocumentMetadata::default(),
//!     embedding: None,
//!     created_at: Utc::now(),
//!     updated_at: Utc::now(),
//! };
//! ```

pub mod embedding;
pub mod extraction;

pub use embedding::{
    KnowledgeCollectionStats, KnowledgeEmbeddingConfig, KnowledgeEmbeddingService,
    KnowledgeIndexStats, KNOWLEDGE_COLLECTION, MAX_KNOWLEDGE_TEXT_LENGTH,
};
pub use extraction::{
    DocumentExtractor, DocumentFormat, ExtractedDocument, ExtractionConfig, ExtractionError,
    ExtractionResult,
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::fmt;
use uuid::Uuid;

use crate::vector::{SearchResult, VectorMetadata};

// ============================================================================
// Knowledge Document Types
// ============================================================================

/// The type of knowledge document.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KnowledgeType {
    /// Step-by-step incident response procedures.
    Runbook,
    /// Threat intelligence analysis and IOCs.
    ThreatIntelReport,
    /// Organizational security policies.
    SecurityPolicy,
    /// Post-incident analysis and lessons learned.
    PostMortem,
    /// External tool or service documentation.
    VendorDocumentation,
    /// Threat actor or campaign profiles.
    ThreatProfile,
    /// Best practice guides and recommendations.
    BestPractice,
    /// Tool usage and configuration guides.
    ToolGuide,
}

impl KnowledgeType {
    /// Returns the string representation for database storage.
    pub fn as_str(&self) -> &'static str {
        match self {
            KnowledgeType::Runbook => "runbook",
            KnowledgeType::ThreatIntelReport => "threat_intel_report",
            KnowledgeType::SecurityPolicy => "security_policy",
            KnowledgeType::PostMortem => "post_mortem",
            KnowledgeType::VendorDocumentation => "vendor_documentation",
            KnowledgeType::ThreatProfile => "threat_profile",
            KnowledgeType::BestPractice => "best_practice",
            KnowledgeType::ToolGuide => "tool_guide",
        }
    }

    /// Parse from database string.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "runbook" => Some(KnowledgeType::Runbook),
            "threat_intel_report" => Some(KnowledgeType::ThreatIntelReport),
            "security_policy" => Some(KnowledgeType::SecurityPolicy),
            "post_mortem" => Some(KnowledgeType::PostMortem),
            "vendor_documentation" => Some(KnowledgeType::VendorDocumentation),
            "threat_profile" => Some(KnowledgeType::ThreatProfile),
            "best_practice" => Some(KnowledgeType::BestPractice),
            "tool_guide" => Some(KnowledgeType::ToolGuide),
            _ => None,
        }
    }

    /// Returns all knowledge types.
    pub fn all() -> &'static [KnowledgeType] {
        &[
            KnowledgeType::Runbook,
            KnowledgeType::ThreatIntelReport,
            KnowledgeType::SecurityPolicy,
            KnowledgeType::PostMortem,
            KnowledgeType::VendorDocumentation,
            KnowledgeType::ThreatProfile,
            KnowledgeType::BestPractice,
            KnowledgeType::ToolGuide,
        ]
    }

    /// Returns a human-readable description of the type.
    pub fn description(&self) -> &'static str {
        match self {
            KnowledgeType::Runbook => "Step-by-step incident response procedures",
            KnowledgeType::ThreatIntelReport => "Threat intelligence analysis and IOCs",
            KnowledgeType::SecurityPolicy => "Organizational security policies",
            KnowledgeType::PostMortem => "Post-incident analysis and lessons learned",
            KnowledgeType::VendorDocumentation => "External tool or service documentation",
            KnowledgeType::ThreatProfile => "Threat actor or campaign profiles",
            KnowledgeType::BestPractice => "Best practice guides and recommendations",
            KnowledgeType::ToolGuide => "Tool usage and configuration guides",
        }
    }
}

impl fmt::Display for KnowledgeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ============================================================================
// Document Metadata
// ============================================================================

/// Metadata associated with a knowledge document.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DocumentMetadata {
    /// Document author or contributor.
    #[serde(default)]
    pub author: Option<String>,

    /// Version string (e.g., "1.0", "2.3").
    #[serde(default)]
    pub version: Option<String>,

    /// Source URL or reference.
    #[serde(default)]
    pub source_url: Option<String>,

    /// MITRE ATT&CK technique IDs this document relates to.
    #[serde(default)]
    pub mitre_techniques: Vec<String>,

    /// Related incident types or categories.
    #[serde(default)]
    pub related_incident_types: Vec<String>,

    /// Keywords for enhanced searchability.
    #[serde(default)]
    pub keywords: Vec<String>,

    /// Custom tags for categorization.
    #[serde(default)]
    pub tags: Vec<String>,

    /// Original file format (e.g., "markdown", "pdf", "html").
    #[serde(default)]
    pub original_format: Option<String>,

    /// Original filename if uploaded.
    #[serde(default)]
    pub original_filename: Option<String>,

    /// File size in bytes (if applicable).
    #[serde(default)]
    pub file_size: Option<u64>,

    /// Additional custom fields.
    #[serde(default)]
    pub custom: HashMap<String, Value>,
}

impl DocumentMetadata {
    /// Create empty metadata.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create metadata with an author.
    pub fn with_author(mut self, author: impl Into<String>) -> Self {
        self.author = Some(author.into());
        self
    }

    /// Set the version.
    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }

    /// Set the source URL.
    pub fn with_source_url(mut self, url: impl Into<String>) -> Self {
        self.source_url = Some(url.into());
        self
    }

    /// Add MITRE techniques.
    pub fn with_mitre_techniques(mut self, techniques: Vec<String>) -> Self {
        self.mitre_techniques = techniques;
        self
    }

    /// Add related incident types.
    pub fn with_related_incident_types(mut self, types: Vec<String>) -> Self {
        self.related_incident_types = types;
        self
    }

    /// Add keywords.
    pub fn with_keywords(mut self, keywords: Vec<String>) -> Self {
        self.keywords = keywords;
        self
    }

    /// Add tags.
    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }

    /// Set original format.
    pub fn with_original_format(mut self, format: impl Into<String>) -> Self {
        self.original_format = Some(format.into());
        self
    }

    /// Set original filename.
    pub fn with_original_filename(mut self, filename: impl Into<String>) -> Self {
        self.original_filename = Some(filename.into());
        self
    }

    /// Add a custom field.
    pub fn with_custom(mut self, key: impl Into<String>, value: Value) -> Self {
        self.custom.insert(key.into(), value);
        self
    }

    /// Convert to JSON value.
    pub fn to_json(&self) -> Value {
        serde_json::to_value(self).unwrap_or(Value::Object(Default::default()))
    }
}

// ============================================================================
// Knowledge Document
// ============================================================================

/// A knowledge base document.
///
/// Represents organizational knowledge such as runbooks, threat intel reports,
/// security policies, and vendor documentation that can be indexed for RAG.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnowledgeDocument {
    /// Unique document identifier.
    pub id: Uuid,

    /// Tenant this document belongs to.
    pub tenant_id: Uuid,

    /// Document type.
    pub doc_type: KnowledgeType,

    /// Document title.
    pub title: String,

    /// Document content (plain text or markdown).
    pub content: String,

    /// Document summary (optional, auto-generated if not provided).
    #[serde(default)]
    pub summary: Option<String>,

    /// Additional metadata.
    #[serde(default)]
    pub metadata: DocumentMetadata,

    /// Vector embedding (computed on indexing).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub embedding: Option<Vec<f32>>,

    /// Whether the document is active/visible.
    #[serde(default = "default_true")]
    pub is_active: bool,

    /// When the document was created.
    pub created_at: DateTime<Utc>,

    /// When the document was last updated.
    pub updated_at: DateTime<Utc>,

    /// When the document was last indexed (if ever).
    #[serde(default)]
    pub indexed_at: Option<DateTime<Utc>>,

    /// User who created the document.
    #[serde(default)]
    pub created_by: Option<Uuid>,

    /// User who last updated the document.
    #[serde(default)]
    pub updated_by: Option<Uuid>,
}

fn default_true() -> bool {
    true
}

impl KnowledgeDocument {
    /// Create a new knowledge document.
    pub fn new(
        tenant_id: Uuid,
        doc_type: KnowledgeType,
        title: impl Into<String>,
        content: impl Into<String>,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            tenant_id,
            doc_type,
            title: title.into(),
            content: content.into(),
            summary: None,
            metadata: DocumentMetadata::default(),
            embedding: None,
            is_active: true,
            created_at: now,
            updated_at: now,
            indexed_at: None,
            created_by: None,
            updated_by: None,
        }
    }

    /// Set the document summary.
    pub fn with_summary(mut self, summary: impl Into<String>) -> Self {
        self.summary = Some(summary.into());
        self
    }

    /// Set document metadata.
    pub fn with_metadata(mut self, metadata: DocumentMetadata) -> Self {
        self.metadata = metadata;
        self
    }

    /// Set the creator.
    pub fn with_created_by(mut self, user_id: Uuid) -> Self {
        self.created_by = Some(user_id);
        self
    }

    /// Mark as inactive.
    pub fn deactivate(&mut self) {
        self.is_active = false;
        self.updated_at = Utc::now();
    }

    /// Mark as active.
    pub fn activate(&mut self) {
        self.is_active = true;
        self.updated_at = Utc::now();
    }

    /// Update the content.
    pub fn update_content(&mut self, content: impl Into<String>, updated_by: Option<Uuid>) {
        self.content = content.into();
        self.updated_at = Utc::now();
        self.updated_by = updated_by;
        // Clear embedding since content changed
        self.embedding = None;
        self.indexed_at = None;
    }

    /// Get the text to be embedded.
    ///
    /// Combines title, summary, content, and metadata keywords for rich embedding.
    pub fn to_embedding_text(&self) -> String {
        let mut parts = Vec::new();

        // Title (emphasized)
        parts.push(format!("Title: {}", self.title));

        // Document type
        parts.push(format!("Type: {}", self.doc_type.description()));

        // Summary if available
        if let Some(ref summary) = self.summary {
            parts.push(format!("Summary: {}", summary));
        }

        // Main content
        parts.push(self.content.clone());

        // Keywords from metadata
        if !self.metadata.keywords.is_empty() {
            parts.push(format!("Keywords: {}", self.metadata.keywords.join(", ")));
        }

        // MITRE techniques
        if !self.metadata.mitre_techniques.is_empty() {
            parts.push(format!(
                "MITRE ATT&CK: {}",
                self.metadata.mitre_techniques.join(", ")
            ));
        }

        // Related incident types
        if !self.metadata.related_incident_types.is_empty() {
            parts.push(format!(
                "Related Incident Types: {}",
                self.metadata.related_incident_types.join(", ")
            ));
        }

        // Tags
        if !self.metadata.tags.is_empty() {
            parts.push(format!("Tags: {}", self.metadata.tags.join(", ")));
        }

        parts.join("\n\n")
    }

    /// Convert to vector metadata for storage.
    pub fn to_vector_metadata(&self) -> VectorMetadata {
        use serde_json::json;

        VectorMetadata::new()
            .with_field("doc_type", json!("knowledge"))
            .with_field("knowledge_type", json!(self.doc_type.as_str()))
            .with_field("tenant_id", json!(self.tenant_id.to_string()))
            .with_field("title", json!(self.title))
            .with_field("is_active", json!(self.is_active))
            .with_field("mitre_techniques", json!(self.metadata.mitre_techniques))
            .with_field("tags", json!(self.metadata.tags))
            .with_field("keywords", json!(self.metadata.keywords))
            .with_field(
                "related_incident_types",
                json!(self.metadata.related_incident_types),
            )
            .with_field("created_at", json!(self.created_at.to_rfc3339()))
            .with_field("updated_at", json!(self.updated_at.to_rfc3339()))
            .with_field("indexed_at", json!(self.indexed_at.map(|t| t.to_rfc3339())))
    }
}

// ============================================================================
// Create/Update DTOs
// ============================================================================

/// Request to create a new knowledge document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateKnowledgeDocument {
    /// Document type.
    pub doc_type: KnowledgeType,

    /// Document title.
    pub title: String,

    /// Document content (plain text or markdown).
    pub content: String,

    /// Optional summary.
    #[serde(default)]
    pub summary: Option<String>,

    /// Optional metadata.
    #[serde(default)]
    pub metadata: Option<DocumentMetadata>,
}

impl CreateKnowledgeDocument {
    /// Build a KnowledgeDocument from this request.
    pub fn build(self, tenant_id: Uuid, created_by: Option<Uuid>) -> KnowledgeDocument {
        let mut doc = KnowledgeDocument::new(tenant_id, self.doc_type, self.title, self.content);

        if let Some(summary) = self.summary {
            doc.summary = Some(summary);
        }

        if let Some(metadata) = self.metadata {
            doc.metadata = metadata;
        }

        doc.created_by = created_by;

        doc
    }
}

/// Request to update an existing knowledge document.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpdateKnowledgeDocument {
    /// Updated title (optional).
    #[serde(default)]
    pub title: Option<String>,

    /// Updated content (optional).
    #[serde(default)]
    pub content: Option<String>,

    /// Updated summary (optional).
    #[serde(default)]
    pub summary: Option<String>,

    /// Updated document type (optional).
    #[serde(default)]
    pub doc_type: Option<KnowledgeType>,

    /// Updated metadata (optional, replaces existing).
    #[serde(default)]
    pub metadata: Option<DocumentMetadata>,

    /// Update active status.
    #[serde(default)]
    pub is_active: Option<bool>,
}

impl UpdateKnowledgeDocument {
    /// Apply this update to a document.
    pub fn apply(&self, doc: &mut KnowledgeDocument, updated_by: Option<Uuid>) {
        let mut content_changed = false;

        if let Some(ref title) = self.title {
            doc.title = title.clone();
            content_changed = true;
        }

        if let Some(ref content) = self.content {
            doc.content = content.clone();
            content_changed = true;
        }

        if let Some(ref summary) = self.summary {
            doc.summary = Some(summary.clone());
        }

        if let Some(doc_type) = self.doc_type {
            doc.doc_type = doc_type;
        }

        if let Some(ref metadata) = self.metadata {
            doc.metadata = metadata.clone();
            content_changed = true; // Metadata affects embedding
        }

        if let Some(is_active) = self.is_active {
            doc.is_active = is_active;
        }

        doc.updated_at = Utc::now();
        doc.updated_by = updated_by;

        // Clear embedding if content changed
        if content_changed {
            doc.embedding = None;
            doc.indexed_at = None;
        }
    }
}

// ============================================================================
// Search Results
// ============================================================================

/// A knowledge document search result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnowledgeSearchResult {
    /// Document ID.
    pub document_id: Uuid,

    /// Document title.
    pub title: String,

    /// Document type.
    pub doc_type: KnowledgeType,

    /// Similarity score (0.0 to 1.0).
    pub score: f32,

    /// Content snippet (truncated).
    #[serde(default)]
    pub snippet: Option<String>,

    /// Document tags.
    pub tags: Vec<String>,

    /// MITRE techniques.
    pub mitre_techniques: Vec<String>,
}

impl KnowledgeSearchResult {
    /// Create from a vector search result.
    pub fn from_search_result(result: &SearchResult, snippet: Option<String>) -> Option<Self> {
        let document_id = Uuid::parse_str(&result.id).ok()?;

        let title = result
            .metadata
            .get_str("title")
            .unwrap_or_default()
            .to_string();

        let doc_type = result
            .metadata
            .get_str("knowledge_type")
            .and_then(KnowledgeType::parse)
            .unwrap_or(KnowledgeType::VendorDocumentation);

        let tags = result
            .metadata
            .get("tags")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        let mitre_techniques = result
            .metadata
            .get("mitre_techniques")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        Some(Self {
            document_id,
            title,
            doc_type,
            score: result.score,
            snippet,
            tags,
            mitre_techniques,
        })
    }
}

// ============================================================================
// Query Filters
// ============================================================================

/// Filter criteria for querying knowledge documents.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KnowledgeFilter {
    /// Filter by document types.
    #[serde(default)]
    pub doc_types: Option<Vec<KnowledgeType>>,

    /// Filter by tags (any match).
    #[serde(default)]
    pub tags: Option<Vec<String>>,

    /// Filter by MITRE techniques (any match).
    #[serde(default)]
    pub mitre_techniques: Option<Vec<String>>,

    /// Filter by active status.
    #[serde(default)]
    pub is_active: Option<bool>,

    /// Full-text search query.
    #[serde(default)]
    pub search_query: Option<String>,

    /// Created after this timestamp.
    #[serde(default)]
    pub created_after: Option<DateTime<Utc>>,

    /// Created before this timestamp.
    #[serde(default)]
    pub created_before: Option<DateTime<Utc>>,

    /// Maximum results to return.
    #[serde(default)]
    pub limit: Option<usize>,

    /// Offset for pagination.
    #[serde(default)]
    pub offset: Option<usize>,
}

impl KnowledgeFilter {
    /// Create an empty filter (returns all).
    pub fn new() -> Self {
        Self::default()
    }

    /// Filter by document type.
    pub fn with_doc_type(mut self, doc_type: KnowledgeType) -> Self {
        self.doc_types = Some(vec![doc_type]);
        self
    }

    /// Filter by document types.
    pub fn with_doc_types(mut self, doc_types: Vec<KnowledgeType>) -> Self {
        self.doc_types = Some(doc_types);
        self
    }

    /// Filter by tags.
    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = Some(tags);
        self
    }

    /// Filter by MITRE techniques.
    pub fn with_mitre_techniques(mut self, techniques: Vec<String>) -> Self {
        self.mitre_techniques = Some(techniques);
        self
    }

    /// Filter by active status.
    pub fn with_active(mut self, is_active: bool) -> Self {
        self.is_active = Some(is_active);
        self
    }

    /// Set search query.
    pub fn with_search_query(mut self, query: impl Into<String>) -> Self {
        self.search_query = Some(query.into());
        self
    }

    /// Set limit.
    pub fn with_limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Set offset for pagination.
    pub fn with_offset(mut self, offset: usize) -> Self {
        self.offset = Some(offset);
        self
    }
}

// ============================================================================
// Statistics
// ============================================================================

/// Statistics about the knowledge base.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KnowledgeStats {
    /// Total number of documents.
    pub total_documents: u64,

    /// Number of indexed documents.
    pub indexed_documents: u64,

    /// Documents by type.
    pub by_type: HashMap<String, u64>,

    /// Top tags with counts.
    pub top_tags: Vec<(String, u64)>,

    /// Top MITRE techniques with counts.
    pub top_mitre_techniques: Vec<(String, u64)>,
}

// ============================================================================
// Article Status & Enhanced Knowledge Article
// ============================================================================

/// Status of a knowledge article.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArticleStatus {
    /// Article is in draft form, not yet published.
    Draft,
    /// Article is published and visible.
    Published,
    /// Article has been archived (still accessible but not in default searches).
    Archived,
    /// Article is deprecated and should not be used.
    Deprecated,
}

impl ArticleStatus {
    /// Returns the string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            ArticleStatus::Draft => "draft",
            ArticleStatus::Published => "published",
            ArticleStatus::Archived => "archived",
            ArticleStatus::Deprecated => "deprecated",
        }
    }

    /// Parse from string.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "draft" => Some(ArticleStatus::Draft),
            "published" => Some(ArticleStatus::Published),
            "archived" => Some(ArticleStatus::Archived),
            "deprecated" => Some(ArticleStatus::Deprecated),
            _ => None,
        }
    }

    /// Returns all statuses.
    pub fn all() -> &'static [ArticleStatus] {
        &[
            ArticleStatus::Draft,
            ArticleStatus::Published,
            ArticleStatus::Archived,
            ArticleStatus::Deprecated,
        ]
    }
}

impl fmt::Display for ArticleStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// An enhanced knowledge article with richer metadata.
///
/// Extends `KnowledgeDocument` with relational fields for incidents,
/// MITRE techniques, authorship, and lifecycle status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnowledgeArticle {
    /// The underlying knowledge document.
    #[serde(flatten)]
    pub document: KnowledgeDocument,

    /// Related incident IDs.
    #[serde(default)]
    pub related_incidents: Vec<Uuid>,

    /// Related MITRE ATT&CK technique IDs (e.g., "T1566.001").
    #[serde(default)]
    pub related_techniques: Vec<String>,

    /// Author user ID.
    #[serde(default)]
    pub author_id: Option<Uuid>,

    /// Article lifecycle status.
    #[serde(default = "default_article_status")]
    pub status: ArticleStatus,
}

fn default_article_status() -> ArticleStatus {
    ArticleStatus::Draft
}

impl KnowledgeArticle {
    /// Create a new knowledge article from a document.
    pub fn from_document(document: KnowledgeDocument) -> Self {
        Self {
            document,
            related_incidents: Vec::new(),
            related_techniques: Vec::new(),
            author_id: None,
            status: ArticleStatus::Draft,
        }
    }

    /// Set related incidents.
    pub fn with_related_incidents(mut self, incidents: Vec<Uuid>) -> Self {
        self.related_incidents = incidents;
        self
    }

    /// Set related MITRE techniques.
    pub fn with_related_techniques(mut self, techniques: Vec<String>) -> Self {
        self.related_techniques = techniques;
        self
    }

    /// Set the author.
    pub fn with_author(mut self, author_id: Uuid) -> Self {
        self.author_id = Some(author_id);
        self
    }

    /// Set the status.
    pub fn with_status(mut self, status: ArticleStatus) -> Self {
        self.status = status;
        self
    }

    /// Publish the article.
    pub fn publish(&mut self) {
        self.status = ArticleStatus::Published;
        self.document.updated_at = Utc::now();
    }

    /// Archive the article.
    pub fn archive(&mut self) {
        self.status = ArticleStatus::Archived;
        self.document.updated_at = Utc::now();
    }
}

// ============================================================================
// Knowledge Search Query
// ============================================================================

/// A structured search query for knowledge documents.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KnowledgeSearchQuery {
    /// Search text.
    pub text: String,

    /// Optional filters.
    #[serde(default)]
    pub filters: KnowledgeFilters,

    /// Maximum results to return.
    #[serde(default)]
    pub limit: Option<usize>,
}

/// Filters for knowledge search.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KnowledgeFilters {
    /// Filter by article types.
    #[serde(default)]
    pub article_types: Option<Vec<KnowledgeType>>,

    /// Filter by tags.
    #[serde(default)]
    pub tags: Option<Vec<String>>,

    /// Filter by date range (start).
    #[serde(default)]
    pub date_from: Option<DateTime<Utc>>,

    /// Filter by date range (end).
    #[serde(default)]
    pub date_to: Option<DateTime<Utc>>,

    /// Filter by article status.
    #[serde(default)]
    pub status: Option<Vec<ArticleStatus>>,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_knowledge_type_serialization() {
        assert_eq!(KnowledgeType::Runbook.as_str(), "runbook");
        assert_eq!(
            KnowledgeType::ThreatIntelReport.as_str(),
            "threat_intel_report"
        );
        assert_eq!(KnowledgeType::SecurityPolicy.as_str(), "security_policy");
        assert_eq!(KnowledgeType::PostMortem.as_str(), "post_mortem");
        assert_eq!(
            KnowledgeType::VendorDocumentation.as_str(),
            "vendor_documentation"
        );
        assert_eq!(KnowledgeType::ThreatProfile.as_str(), "threat_profile");
        assert_eq!(KnowledgeType::BestPractice.as_str(), "best_practice");
        assert_eq!(KnowledgeType::ToolGuide.as_str(), "tool_guide");
    }

    #[test]
    fn test_knowledge_type_from_str() {
        assert_eq!(
            KnowledgeType::parse("runbook"),
            Some(KnowledgeType::Runbook)
        );
        assert_eq!(
            KnowledgeType::parse("threat_intel_report"),
            Some(KnowledgeType::ThreatIntelReport)
        );
        assert_eq!(
            KnowledgeType::parse("threat_profile"),
            Some(KnowledgeType::ThreatProfile)
        );
        assert_eq!(
            KnowledgeType::parse("best_practice"),
            Some(KnowledgeType::BestPractice)
        );
        assert_eq!(
            KnowledgeType::parse("tool_guide"),
            Some(KnowledgeType::ToolGuide)
        );
        assert_eq!(KnowledgeType::parse("invalid"), None);
    }

    #[test]
    fn test_knowledge_type_all_includes_new_types() {
        let all = KnowledgeType::all();
        assert_eq!(all.len(), 8);
        assert!(all.contains(&KnowledgeType::ThreatProfile));
        assert!(all.contains(&KnowledgeType::BestPractice));
        assert!(all.contains(&KnowledgeType::ToolGuide));
    }

    #[test]
    fn test_document_creation() {
        let tenant_id = Uuid::new_v4();
        let doc = KnowledgeDocument::new(
            tenant_id,
            KnowledgeType::Runbook,
            "Phishing Response",
            "## Steps\n1. Verify alert\n2. Contain threat",
        );

        assert_eq!(doc.doc_type, KnowledgeType::Runbook);
        assert_eq!(doc.title, "Phishing Response");
        assert!(doc.is_active);
        assert!(doc.embedding.is_none());
        assert!(doc.indexed_at.is_none());
    }

    #[test]
    fn test_document_metadata_builder() {
        let metadata = DocumentMetadata::new()
            .with_author("Security Team")
            .with_version("2.0")
            .with_tags(vec!["phishing".to_string(), "email".to_string()])
            .with_mitre_techniques(vec!["T1566".to_string(), "T1566.001".to_string()])
            .with_keywords(vec!["credential".to_string(), "theft".to_string()]);

        assert_eq!(metadata.author, Some("Security Team".to_string()));
        assert_eq!(metadata.version, Some("2.0".to_string()));
        assert_eq!(metadata.tags.len(), 2);
        assert_eq!(metadata.mitre_techniques.len(), 2);
        assert_eq!(metadata.keywords.len(), 2);
    }

    #[test]
    fn test_document_embedding_text() {
        let tenant_id = Uuid::new_v4();
        let metadata = DocumentMetadata::new()
            .with_tags(vec!["phishing".to_string()])
            .with_mitre_techniques(vec!["T1566".to_string()])
            .with_keywords(vec!["email".to_string()]);

        let doc = KnowledgeDocument::new(
            tenant_id,
            KnowledgeType::Runbook,
            "Phishing Response",
            "Handle phishing incidents",
        )
        .with_summary("Quick guide for phishing")
        .with_metadata(metadata);

        let text = doc.to_embedding_text();

        assert!(text.contains("Title: Phishing Response"));
        assert!(text.contains("Summary: Quick guide for phishing"));
        assert!(text.contains("Handle phishing incidents"));
        assert!(text.contains("Keywords: email"));
        assert!(text.contains("MITRE ATT&CK: T1566"));
        assert!(text.contains("Tags: phishing"));
    }

    #[test]
    fn test_update_document() {
        let tenant_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let mut doc = KnowledgeDocument::new(
            tenant_id,
            KnowledgeType::Runbook,
            "Original Title",
            "Original content",
        );

        let original_updated = doc.updated_at;

        // Simulate time passing
        std::thread::sleep(std::time::Duration::from_millis(10));

        let update = UpdateKnowledgeDocument {
            title: Some("New Title".to_string()),
            content: Some("New content".to_string()),
            ..Default::default()
        };

        update.apply(&mut doc, Some(user_id));

        assert_eq!(doc.title, "New Title");
        assert_eq!(doc.content, "New content");
        assert_eq!(doc.updated_by, Some(user_id));
        assert!(doc.updated_at > original_updated);
        assert!(doc.embedding.is_none()); // Cleared after content change
        assert!(doc.indexed_at.is_none()); // Cleared after content change
    }

    #[test]
    fn test_create_document_dto() {
        let tenant_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();

        let create = CreateKnowledgeDocument {
            doc_type: KnowledgeType::SecurityPolicy,
            title: "Password Policy".to_string(),
            content: "All passwords must be...".to_string(),
            summary: Some("Password requirements".to_string()),
            metadata: Some(DocumentMetadata::new().with_tags(vec!["policy".to_string()])),
        };

        let doc = create.build(tenant_id, Some(user_id));

        assert_eq!(doc.doc_type, KnowledgeType::SecurityPolicy);
        assert_eq!(doc.title, "Password Policy");
        assert_eq!(doc.summary, Some("Password requirements".to_string()));
        assert_eq!(doc.created_by, Some(user_id));
        assert!(doc.metadata.tags.contains(&"policy".to_string()));
    }

    #[test]
    fn test_knowledge_filter_builder() {
        let filter = KnowledgeFilter::new()
            .with_doc_type(KnowledgeType::Runbook)
            .with_tags(vec!["phishing".to_string()])
            .with_active(true)
            .with_limit(10)
            .with_offset(20);

        assert_eq!(filter.doc_types, Some(vec![KnowledgeType::Runbook]));
        assert_eq!(filter.tags, Some(vec!["phishing".to_string()]));
        assert_eq!(filter.is_active, Some(true));
        assert_eq!(filter.limit, Some(10));
        assert_eq!(filter.offset, Some(20));
    }

    #[test]
    fn test_to_vector_metadata() {
        let tenant_id = Uuid::new_v4();
        let doc = KnowledgeDocument::new(
            tenant_id,
            KnowledgeType::Runbook,
            "Test Doc",
            "Content here",
        );

        let metadata = doc.to_vector_metadata();

        assert_eq!(metadata.get_str("doc_type"), Some("knowledge"));
        assert_eq!(metadata.get_str("knowledge_type"), Some("runbook"));
        assert_eq!(metadata.get_str("title"), Some("Test Doc"));
        assert_eq!(metadata.get_bool("is_active"), Some(true));
    }

    // ========================================================================
    // Article Status Tests
    // ========================================================================

    #[test]
    fn test_article_status_serialization() {
        assert_eq!(ArticleStatus::Draft.as_str(), "draft");
        assert_eq!(ArticleStatus::Published.as_str(), "published");
        assert_eq!(ArticleStatus::Archived.as_str(), "archived");
        assert_eq!(ArticleStatus::Deprecated.as_str(), "deprecated");
    }

    #[test]
    fn test_article_status_parse() {
        assert_eq!(ArticleStatus::parse("draft"), Some(ArticleStatus::Draft));
        assert_eq!(
            ArticleStatus::parse("published"),
            Some(ArticleStatus::Published)
        );
        assert_eq!(
            ArticleStatus::parse("archived"),
            Some(ArticleStatus::Archived)
        );
        assert_eq!(
            ArticleStatus::parse("deprecated"),
            Some(ArticleStatus::Deprecated)
        );
        assert_eq!(ArticleStatus::parse("invalid"), None);
    }

    #[test]
    fn test_article_status_all() {
        assert_eq!(ArticleStatus::all().len(), 4);
    }

    // ========================================================================
    // Knowledge Article Tests
    // ========================================================================

    #[test]
    fn test_knowledge_article_from_document() {
        let tenant_id = Uuid::new_v4();
        let doc = KnowledgeDocument::new(
            tenant_id,
            KnowledgeType::BestPractice,
            "MFA Best Practices",
            "Always use MFA for admin accounts.",
        );

        let article = KnowledgeArticle::from_document(doc);

        assert_eq!(article.document.doc_type, KnowledgeType::BestPractice);
        assert_eq!(article.status, ArticleStatus::Draft);
        assert!(article.related_incidents.is_empty());
        assert!(article.related_techniques.is_empty());
        assert!(article.author_id.is_none());
    }

    #[test]
    fn test_knowledge_article_builder() {
        let tenant_id = Uuid::new_v4();
        let author_id = Uuid::new_v4();
        let incident_id = Uuid::new_v4();
        let doc = KnowledgeDocument::new(
            tenant_id,
            KnowledgeType::ThreatProfile,
            "APT29 Profile",
            "APT29 overview content.",
        );

        let article = KnowledgeArticle::from_document(doc)
            .with_author(author_id)
            .with_related_incidents(vec![incident_id])
            .with_related_techniques(vec!["T1059".to_string(), "T1071".to_string()])
            .with_status(ArticleStatus::Published);

        assert_eq!(article.author_id, Some(author_id));
        assert_eq!(article.related_incidents, vec![incident_id]);
        assert_eq!(article.related_techniques.len(), 2);
        assert_eq!(article.status, ArticleStatus::Published);
    }

    #[test]
    fn test_knowledge_article_publish_archive() {
        let tenant_id = Uuid::new_v4();
        let doc = KnowledgeDocument::new(
            tenant_id,
            KnowledgeType::ToolGuide,
            "Splunk Guide",
            "How to use Splunk.",
        );

        let mut article = KnowledgeArticle::from_document(doc);
        assert_eq!(article.status, ArticleStatus::Draft);

        article.publish();
        assert_eq!(article.status, ArticleStatus::Published);

        article.archive();
        assert_eq!(article.status, ArticleStatus::Archived);
    }

    // ========================================================================
    // Search Query / Filters Tests
    // ========================================================================

    #[test]
    fn test_knowledge_search_query_default() {
        let query = KnowledgeSearchQuery {
            text: "phishing playbook".to_string(),
            ..Default::default()
        };

        assert_eq!(query.text, "phishing playbook");
        assert!(query.filters.article_types.is_none());
        assert!(query.filters.tags.is_none());
        assert!(query.limit.is_none());
    }

    #[test]
    fn test_knowledge_filters() {
        let filters = KnowledgeFilters {
            article_types: Some(vec![KnowledgeType::Runbook, KnowledgeType::BestPractice]),
            tags: Some(vec!["phishing".to_string()]),
            date_from: None,
            date_to: None,
            status: Some(vec![ArticleStatus::Published]),
        };

        assert_eq!(filters.article_types.as_ref().unwrap().len(), 2);
        assert_eq!(filters.tags.as_ref().unwrap().len(), 1);
        assert_eq!(filters.status.as_ref().unwrap().len(), 1);
    }
}
