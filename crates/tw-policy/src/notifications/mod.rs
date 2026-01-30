//! Notification system for Triage Warden.
//!
//! This module provides a flexible notification system for sending alerts,
//! approval requests, and escalations through various channels.

mod slack;
mod webhook;

pub use slack::SlackNotifier;
pub use webhook::WebhookNotifier;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, error, info, instrument, warn};
use uuid::Uuid;

/// Errors that can occur when sending notifications.
#[derive(Error, Debug)]
pub enum NotificationError {
    /// Failed to send the notification.
    #[error("Failed to send notification: {0}")]
    SendFailed(String),

    /// Invalid configuration.
    #[error("Invalid notification configuration: {0}")]
    InvalidConfig(String),

    /// Rate limited by the notification service.
    #[error("Rate limited: {0}")]
    RateLimited(String),
}

/// Type of notification being sent.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum NotificationType {
    /// Approval is required for an action.
    ApprovalRequired,
    /// Escalation of an existing issue.
    Escalation,
    /// Alert requiring attention.
    Alert,
    /// Informational notification.
    Info,
}

impl std::fmt::Display for NotificationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NotificationType::ApprovalRequired => write!(f, "Approval Required"),
            NotificationType::Escalation => write!(f, "Escalation"),
            NotificationType::Alert => write!(f, "Alert"),
            NotificationType::Info => write!(f, "Info"),
        }
    }
}

/// Priority level for notifications.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum NotificationPriority {
    /// Low priority, can be addressed later.
    Low,
    /// Normal priority.
    Normal,
    /// High priority, should be addressed soon.
    High,
    /// Urgent priority, requires immediate attention.
    Urgent,
}

impl std::fmt::Display for NotificationPriority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NotificationPriority::Low => write!(f, "Low"),
            NotificationPriority::Normal => write!(f, "Normal"),
            NotificationPriority::High => write!(f, "High"),
            NotificationPriority::Urgent => write!(f, "Urgent"),
        }
    }
}

impl NotificationPriority {
    /// Returns a color hex code for the priority level.
    pub fn color(&self) -> &'static str {
        match self {
            NotificationPriority::Low => "#36a64f",    // Green
            NotificationPriority::Normal => "#2196F3", // Blue
            NotificationPriority::High => "#ff9800",   // Orange
            NotificationPriority::Urgent => "#f44336", // Red
        }
    }
}

/// A notification to be sent through one or more channels.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Notification {
    /// Unique identifier for the notification.
    pub id: Uuid,
    /// Type of notification.
    pub notification_type: NotificationType,
    /// Title of the notification.
    pub title: String,
    /// Message body.
    pub message: String,
    /// Priority level.
    pub priority: NotificationPriority,
    /// Additional metadata.
    pub metadata: HashMap<String, String>,
    /// When the notification was created.
    pub created_at: DateTime<Utc>,
}

impl Notification {
    /// Creates a new notification.
    pub fn new(
        notification_type: NotificationType,
        title: impl Into<String>,
        message: impl Into<String>,
        priority: NotificationPriority,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            notification_type,
            title: title.into(),
            message: message.into(),
            priority,
            metadata: HashMap::new(),
            created_at: Utc::now(),
        }
    }

    /// Creates a new approval required notification.
    pub fn approval_required(
        title: impl Into<String>,
        message: impl Into<String>,
        priority: NotificationPriority,
    ) -> Self {
        Self::new(NotificationType::ApprovalRequired, title, message, priority)
    }

    /// Creates a new escalation notification.
    pub fn escalation(
        title: impl Into<String>,
        message: impl Into<String>,
        priority: NotificationPriority,
    ) -> Self {
        Self::new(NotificationType::Escalation, title, message, priority)
    }

    /// Creates a new alert notification.
    pub fn alert(
        title: impl Into<String>,
        message: impl Into<String>,
        priority: NotificationPriority,
    ) -> Self {
        Self::new(NotificationType::Alert, title, message, priority)
    }

    /// Creates a new info notification.
    pub fn info(title: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(
            NotificationType::Info,
            title,
            message,
            NotificationPriority::Low,
        )
    }

    /// Adds metadata to the notification.
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}

/// Trait for notification channels.
#[async_trait]
pub trait Notifier: Send + Sync {
    /// Sends a notification.
    async fn send(&self, notification: &Notification) -> Result<(), NotificationError>;

    /// Returns the name of the notifier.
    fn name(&self) -> &str;
}

/// A notifier that logs notifications via tracing (useful for testing).
#[derive(Debug, Default)]
pub struct LogNotifier {
    name: String,
}

impl LogNotifier {
    /// Creates a new log notifier.
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}

#[async_trait]
impl Notifier for LogNotifier {
    #[instrument(skip(self, notification), fields(notifier = %self.name))]
    async fn send(&self, notification: &Notification) -> Result<(), NotificationError> {
        info!(
            notification_id = %notification.id,
            notification_type = ?notification.notification_type,
            priority = ?notification.priority,
            title = %notification.title,
            "Notification sent via LogNotifier"
        );
        debug!(message = %notification.message, "Notification details");
        Ok(())
    }

    fn name(&self) -> &str {
        &self.name
    }
}

/// A composite notifier that sends to multiple notification channels.
pub struct CompositeNotifier {
    notifiers: Vec<Arc<dyn Notifier>>,
    /// Whether to continue sending if one notifier fails.
    continue_on_error: bool,
}

impl CompositeNotifier {
    /// Creates a new composite notifier.
    pub fn new() -> Self {
        Self {
            notifiers: Vec::new(),
            continue_on_error: true,
        }
    }

    /// Sets whether to continue sending if one notifier fails.
    pub fn with_continue_on_error(mut self, continue_on_error: bool) -> Self {
        self.continue_on_error = continue_on_error;
        self
    }

    /// Adds a notifier to the composite.
    pub fn add_notifier<N: Notifier + 'static>(mut self, notifier: N) -> Self {
        self.notifiers.push(Arc::new(notifier));
        self
    }

    /// Adds a notifier wrapped in Arc.
    pub fn add_arc_notifier(mut self, notifier: Arc<dyn Notifier>) -> Self {
        self.notifiers.push(notifier);
        self
    }

    /// Returns the number of notifiers.
    pub fn len(&self) -> usize {
        self.notifiers.len()
    }

    /// Returns true if there are no notifiers.
    pub fn is_empty(&self) -> bool {
        self.notifiers.is_empty()
    }
}

impl Default for CompositeNotifier {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Notifier for CompositeNotifier {
    #[instrument(skip(self, notification), fields(notifier_count = %self.notifiers.len()))]
    async fn send(&self, notification: &Notification) -> Result<(), NotificationError> {
        if self.notifiers.is_empty() {
            warn!("CompositeNotifier has no notifiers configured");
            return Ok(());
        }

        let mut errors = Vec::new();

        for notifier in &self.notifiers {
            match notifier.send(notification).await {
                Ok(()) => {
                    debug!(notifier = %notifier.name(), "Notification sent successfully");
                }
                Err(e) => {
                    error!(
                        notifier = %notifier.name(),
                        error = %e,
                        "Failed to send notification"
                    );
                    if !self.continue_on_error {
                        return Err(e);
                    }
                    errors.push(format!("{}: {}", notifier.name(), e));
                }
            }
        }

        if !errors.is_empty() {
            warn!(
                error_count = errors.len(),
                total_notifiers = self.notifiers.len(),
                "Some notifications failed to send"
            );
            // Return an error summarizing all failures if all notifiers failed
            if errors.len() == self.notifiers.len() {
                return Err(NotificationError::SendFailed(errors.join("; ")));
            }
        }

        Ok(())
    }

    fn name(&self) -> &str {
        "composite"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn test_notification_creation() {
        let notification = Notification::new(
            NotificationType::Alert,
            "Test Alert",
            "This is a test alert message",
            NotificationPriority::High,
        );

        assert_eq!(notification.notification_type, NotificationType::Alert);
        assert_eq!(notification.title, "Test Alert");
        assert_eq!(notification.message, "This is a test alert message");
        assert_eq!(notification.priority, NotificationPriority::High);
        assert!(notification.metadata.is_empty());
    }

    #[test]
    fn test_notification_with_metadata() {
        let notification = Notification::alert("Test", "Message", NotificationPriority::Normal)
            .with_metadata("incident_id", "INC-123")
            .with_metadata("severity", "high");

        assert_eq!(notification.metadata.len(), 2);
        assert_eq!(
            notification.metadata.get("incident_id"),
            Some(&"INC-123".to_string())
        );
        assert_eq!(
            notification.metadata.get("severity"),
            Some(&"high".to_string())
        );
    }

    #[test]
    fn test_notification_convenience_constructors() {
        let approval =
            Notification::approval_required("Title", "Message", NotificationPriority::High);
        assert_eq!(
            approval.notification_type,
            NotificationType::ApprovalRequired
        );

        let escalation = Notification::escalation("Title", "Message", NotificationPriority::Urgent);
        assert_eq!(escalation.notification_type, NotificationType::Escalation);

        let alert = Notification::alert("Title", "Message", NotificationPriority::Normal);
        assert_eq!(alert.notification_type, NotificationType::Alert);

        let info = Notification::info("Title", "Message");
        assert_eq!(info.notification_type, NotificationType::Info);
        assert_eq!(info.priority, NotificationPriority::Low);
    }

    #[test]
    fn test_priority_ordering() {
        assert!(NotificationPriority::Urgent > NotificationPriority::High);
        assert!(NotificationPriority::High > NotificationPriority::Normal);
        assert!(NotificationPriority::Normal > NotificationPriority::Low);
    }

    #[test]
    fn test_priority_colors() {
        assert_eq!(NotificationPriority::Low.color(), "#36a64f");
        assert_eq!(NotificationPriority::Normal.color(), "#2196F3");
        assert_eq!(NotificationPriority::High.color(), "#ff9800");
        assert_eq!(NotificationPriority::Urgent.color(), "#f44336");
    }

    #[tokio::test]
    async fn test_log_notifier() {
        let notifier = LogNotifier::new("test-logger");
        let notification = Notification::info("Test", "Test message");

        let result = notifier.send(&notification).await;
        assert!(result.is_ok());
        assert_eq!(notifier.name(), "test-logger");
    }

    /// A mock notifier for testing that tracks call counts and can simulate failures.
    struct MockNotifier {
        name: String,
        call_count: AtomicUsize,
        should_fail: bool,
    }

    impl MockNotifier {
        fn new(name: &str, should_fail: bool) -> Self {
            Self {
                name: name.to_string(),
                call_count: AtomicUsize::new(0),
                should_fail,
            }
        }

        fn call_count(&self) -> usize {
            self.call_count.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl Notifier for MockNotifier {
        async fn send(&self, _notification: &Notification) -> Result<(), NotificationError> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            if self.should_fail {
                Err(NotificationError::SendFailed("Mock failure".to_string()))
            } else {
                Ok(())
            }
        }

        fn name(&self) -> &str {
            &self.name
        }
    }

    #[tokio::test]
    async fn test_composite_notifier_sends_to_all() {
        let notifier1 = Arc::new(MockNotifier::new("notifier1", false));
        let notifier2 = Arc::new(MockNotifier::new("notifier2", false));

        let n1 = notifier1.clone();
        let n2 = notifier2.clone();

        let composite = CompositeNotifier::new()
            .add_arc_notifier(notifier1)
            .add_arc_notifier(notifier2);

        let notification = Notification::info("Test", "Test message");
        let result = composite.send(&notification).await;

        assert!(result.is_ok());
        assert_eq!(n1.call_count(), 1);
        assert_eq!(n2.call_count(), 1);
    }

    #[tokio::test]
    async fn test_composite_notifier_continues_on_error() {
        let notifier1 = Arc::new(MockNotifier::new("notifier1", true)); // fails
        let notifier2 = Arc::new(MockNotifier::new("notifier2", false)); // succeeds

        let n1 = notifier1.clone();
        let n2 = notifier2.clone();

        let composite = CompositeNotifier::new()
            .with_continue_on_error(true)
            .add_arc_notifier(notifier1)
            .add_arc_notifier(notifier2);

        let notification = Notification::info("Test", "Test message");
        let result = composite.send(&notification).await;

        // Should still succeed because continue_on_error is true and not all failed
        assert!(result.is_ok());
        assert_eq!(n1.call_count(), 1);
        assert_eq!(n2.call_count(), 1);
    }

    #[tokio::test]
    async fn test_composite_notifier_stops_on_error() {
        let notifier1 = Arc::new(MockNotifier::new("notifier1", true)); // fails
        let notifier2 = Arc::new(MockNotifier::new("notifier2", false)); // succeeds

        let n1 = notifier1.clone();
        let n2 = notifier2.clone();

        let composite = CompositeNotifier::new()
            .with_continue_on_error(false)
            .add_arc_notifier(notifier1)
            .add_arc_notifier(notifier2);

        let notification = Notification::info("Test", "Test message");
        let result = composite.send(&notification).await;

        assert!(result.is_err());
        assert_eq!(n1.call_count(), 1);
        assert_eq!(n2.call_count(), 0); // Should not be called
    }

    #[tokio::test]
    async fn test_composite_notifier_all_fail() {
        let notifier1 = Arc::new(MockNotifier::new("notifier1", true));
        let notifier2 = Arc::new(MockNotifier::new("notifier2", true));

        let composite = CompositeNotifier::new()
            .with_continue_on_error(true)
            .add_arc_notifier(notifier1)
            .add_arc_notifier(notifier2);

        let notification = Notification::info("Test", "Test message");
        let result = composite.send(&notification).await;

        // Should fail because all notifiers failed
        assert!(result.is_err());
        if let Err(NotificationError::SendFailed(msg)) = result {
            assert!(msg.contains("notifier1"));
            assert!(msg.contains("notifier2"));
        } else {
            panic!("Expected SendFailed error");
        }
    }

    #[tokio::test]
    async fn test_composite_notifier_empty() {
        let composite = CompositeNotifier::new();
        assert!(composite.is_empty());
        assert_eq!(composite.len(), 0);

        let notification = Notification::info("Test", "Test message");
        let result = composite.send(&notification).await;

        // Empty composite should succeed (nothing to fail)
        assert!(result.is_ok());
    }

    #[test]
    fn test_notification_type_display() {
        assert_eq!(
            NotificationType::ApprovalRequired.to_string(),
            "Approval Required"
        );
        assert_eq!(NotificationType::Escalation.to_string(), "Escalation");
        assert_eq!(NotificationType::Alert.to_string(), "Alert");
        assert_eq!(NotificationType::Info.to_string(), "Info");
    }

    #[test]
    fn test_notification_priority_display() {
        assert_eq!(NotificationPriority::Low.to_string(), "Low");
        assert_eq!(NotificationPriority::Normal.to_string(), "Normal");
        assert_eq!(NotificationPriority::High.to_string(), "High");
        assert_eq!(NotificationPriority::Urgent.to_string(), "Urgent");
    }
}
