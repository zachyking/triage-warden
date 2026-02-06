//! Commenting system for incident discussions.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A comment on an incident.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentComment {
    /// Unique comment identifier.
    pub id: Uuid,
    /// The incident this comment belongs to.
    pub incident_id: Uuid,
    /// The user who authored this comment.
    pub author_id: Uuid,
    /// Comment text content.
    pub content: String,
    /// Type of comment.
    pub comment_type: CommentType,
    /// User IDs mentioned in this comment.
    #[serde(default)]
    pub mentions: Vec<Uuid>,
    /// When the comment was created.
    pub created_at: DateTime<Utc>,
    /// When the comment was last updated.
    pub updated_at: DateTime<Utc>,
    /// Whether the comment has been edited since creation.
    pub edited: bool,
}

impl IncidentComment {
    /// Creates a new comment.
    pub fn new(
        incident_id: Uuid,
        author_id: Uuid,
        content: String,
        comment_type: CommentType,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            incident_id,
            author_id,
            content,
            comment_type,
            mentions: Vec::new(),
            created_at: now,
            updated_at: now,
            edited: false,
        }
    }

    /// Creates a new comment with mentions.
    pub fn with_mentions(mut self, mentions: Vec<Uuid>) -> Self {
        self.mentions = mentions;
        self
    }

    /// Updates the comment content and marks it as edited.
    pub fn update_content(&mut self, content: String) {
        self.content = content;
        self.edited = true;
        self.updated_at = Utc::now();
    }

    /// Updates the comment type.
    pub fn update_type(&mut self, comment_type: CommentType) {
        self.comment_type = comment_type;
        self.updated_at = Utc::now();
    }
}

/// The type of comment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommentType {
    /// General notes.
    Note,
    /// Analysis findings.
    Analysis,
    /// Record of an action taken.
    ActionTaken,
    /// Question for discussion.
    Question,
    /// Resolution summary.
    Resolution,
}

impl std::fmt::Display for CommentType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CommentType::Note => write!(f, "note"),
            CommentType::Analysis => write!(f, "analysis"),
            CommentType::ActionTaken => write!(f, "action_taken"),
            CommentType::Question => write!(f, "question"),
            CommentType::Resolution => write!(f, "resolution"),
        }
    }
}

/// Request to create a new comment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateCommentRequest {
    /// Comment text content.
    pub content: String,
    /// Type of comment.
    pub comment_type: CommentType,
    /// User IDs to mention.
    #[serde(default)]
    pub mentions: Vec<Uuid>,
}

/// Request to update an existing comment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateCommentRequest {
    /// Updated content (if provided).
    pub content: Option<String>,
    /// Updated comment type (if provided).
    pub comment_type: Option<CommentType>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_comment() {
        let incident_id = Uuid::new_v4();
        let author_id = Uuid::new_v4();
        let comment = IncidentComment::new(
            incident_id,
            author_id,
            "Suspicious lateral movement detected".to_string(),
            CommentType::Analysis,
        );

        assert_eq!(comment.incident_id, incident_id);
        assert_eq!(comment.author_id, author_id);
        assert_eq!(comment.comment_type, CommentType::Analysis);
        assert!(!comment.edited);
        assert!(comment.mentions.is_empty());
    }

    #[test]
    fn test_comment_with_mentions() {
        let mention1 = Uuid::new_v4();
        let mention2 = Uuid::new_v4();
        let comment = IncidentComment::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            "Can someone review this?".to_string(),
            CommentType::Question,
        )
        .with_mentions(vec![mention1, mention2]);

        assert_eq!(comment.mentions.len(), 2);
        assert!(comment.mentions.contains(&mention1));
    }

    #[test]
    fn test_update_content_marks_edited() {
        let mut comment = IncidentComment::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            "Original".to_string(),
            CommentType::Note,
        );

        assert!(!comment.edited);
        let original_updated = comment.updated_at;

        // Small delay to ensure timestamp difference
        comment.update_content("Updated content".to_string());

        assert!(comment.edited);
        assert_eq!(comment.content, "Updated content");
        assert!(comment.updated_at >= original_updated);
    }

    #[test]
    fn test_update_type() {
        let mut comment = IncidentComment::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            "Blocked the IP".to_string(),
            CommentType::Note,
        );

        comment.update_type(CommentType::ActionTaken);
        assert_eq!(comment.comment_type, CommentType::ActionTaken);
    }

    #[test]
    fn test_comment_type_display() {
        assert_eq!(CommentType::Note.to_string(), "note");
        assert_eq!(CommentType::Analysis.to_string(), "analysis");
        assert_eq!(CommentType::ActionTaken.to_string(), "action_taken");
        assert_eq!(CommentType::Question.to_string(), "question");
        assert_eq!(CommentType::Resolution.to_string(), "resolution");
    }

    #[test]
    fn test_comment_serialization() {
        let comment = IncidentComment::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            "Test comment".to_string(),
            CommentType::Note,
        );

        let json = serde_json::to_string(&comment).unwrap();
        let deserialized: IncidentComment = serde_json::from_str(&json).unwrap();

        assert_eq!(comment.id, deserialized.id);
        assert_eq!(comment.content, deserialized.content);
        assert_eq!(comment.comment_type, deserialized.comment_type);
    }

    #[test]
    fn test_comment_type_serde_snake_case() {
        let json = serde_json::to_string(&CommentType::ActionTaken).unwrap();
        assert_eq!(json, "\"action_taken\"");

        let deserialized: CommentType = serde_json::from_str("\"action_taken\"").unwrap();
        assert_eq!(deserialized, CommentType::ActionTaken);
    }

    #[test]
    fn test_create_comment_request_deserialization() {
        let json = r#"{
            "content": "Found malicious binary",
            "comment_type": "analysis",
            "mentions": []
        }"#;

        let request: CreateCommentRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.content, "Found malicious binary");
        assert_eq!(request.comment_type, CommentType::Analysis);
    }

    #[test]
    fn test_update_comment_request_partial() {
        let json = r#"{"content": "Updated text"}"#;
        let request: UpdateCommentRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.content, Some("Updated text".to_string()));
        assert!(request.comment_type.is_none());
    }
}
