//! Collaboration features for incident management.
//!
//! This module provides:
//! - Incident assignment with auto-assignment rules
//! - Commenting system for incident discussions
//! - Real-time event types for live updates
//! - Activity feed for audit trails
//! - Shift handoff report generation

pub mod activity;
pub mod assignment;
pub mod comment;
pub mod handoff;
pub mod realtime;

pub use activity::{ActivityEntry, ActivityFilter, ActivityType};
pub use assignment::{
    AssigneeTarget, AssignmentCondition, AssignmentEngine, AutoAssignmentRule, IncidentAssignment,
};
pub use comment::{CommentType, CreateCommentRequest, IncidentComment, UpdateCommentRequest};
pub use handoff::{ActionSummary, IncidentSummary, ShiftHandoff, ShiftHandoffRequest};
pub use realtime::{FieldChange, RealtimeEvent, RealtimeSubscription, SubscriptionFilter};
