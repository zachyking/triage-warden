//! Emergency kill switch for Triage Warden.
//!
//! This module provides an emergency kill switch that immediately halts all automation.
//! It uses atomic operations for thread-safe access and broadcast channels for event
//! notifications.

use chrono::{DateTime, Utc};
use std::sync::atomic::{AtomicBool, Ordering};
use thiserror::Error;
use tokio::sync::{broadcast, RwLock};
use tracing::{error, info, warn};

/// Events emitted by the kill switch.
#[derive(Debug, Clone)]
pub enum KillSwitchEvent {
    /// Kill switch was activated.
    Activated {
        /// Who activated the kill switch.
        by: String,
        /// When the kill switch was activated.
        at: DateTime<Utc>,
    },
    /// Kill switch was deactivated.
    Deactivated {
        /// Who deactivated the kill switch.
        by: String,
        /// When the kill switch was deactivated.
        at: DateTime<Utc>,
    },
}

/// Errors that can occur when operating the kill switch.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum KillSwitchError {
    /// Kill switch is already active.
    #[error("Kill switch is already active")]
    AlreadyActive,

    /// Kill switch is not active.
    #[error("Kill switch is not active")]
    NotActive,
}

/// Error returned when checking if the kill switch is active.
///
/// This error type is designed for convenient use with the `?` operator
/// to bail out early when the kill switch is engaged.
#[derive(Error, Debug, Clone)]
#[error("Kill switch is active: automation halted by {activated_by} at {activated_at}")]
pub struct KillSwitchActive {
    /// When the kill switch was activated.
    pub activated_at: DateTime<Utc>,
    /// Who activated the kill switch.
    pub activated_by: String,
}

/// Current status of the kill switch.
#[derive(Debug, Clone)]
pub struct KillSwitchStatus {
    /// Whether the kill switch is currently active.
    pub active: bool,
    /// When the kill switch was activated (if active).
    pub activated_at: Option<DateTime<Utc>>,
    /// Who activated the kill switch (if active).
    pub activated_by: Option<String>,
}

/// Emergency kill switch that immediately halts all automation.
///
/// The kill switch provides a thread-safe mechanism to immediately stop all
/// automated actions in the system. It uses atomic operations for the active
/// flag to ensure consistent reads across threads, and broadcast channels
/// to notify all interested parties when the switch state changes.
///
/// # Example
///
/// ```rust,no_run
/// use tw_policy::kill_switch::KillSwitch;
///
/// #[tokio::main]
/// async fn main() {
///     let kill_switch = KillSwitch::new();
///
///     // Check if automation should proceed
///     if kill_switch.check().is_ok() {
///         // Perform automated action
///     }
///
///     // Activate in emergency
///     kill_switch.activate("security_admin").await.unwrap();
///
///     // Now check() will return an error
///     assert!(kill_switch.check().is_err());
/// }
/// ```
pub struct KillSwitch {
    /// Whether the kill switch is currently active.
    active: AtomicBool,
    /// When the kill switch was activated.
    activated_at: RwLock<Option<DateTime<Utc>>>,
    /// Who activated the kill switch.
    activated_by: RwLock<Option<String>>,
    /// Broadcast sender for kill switch events.
    sender: broadcast::Sender<KillSwitchEvent>,
}

impl KillSwitch {
    /// Creates a new kill switch in the inactive state.
    pub fn new() -> Self {
        let (sender, _) = broadcast::channel(16);
        Self {
            active: AtomicBool::new(false),
            activated_at: RwLock::new(None),
            activated_by: RwLock::new(None),
            sender,
        }
    }

    /// Activates the kill switch, halting all automation.
    ///
    /// # Arguments
    ///
    /// * `activated_by` - Identifier of who is activating the kill switch.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the kill switch was successfully activated,
    /// or `Err(KillSwitchError::AlreadyActive)` if it was already active.
    pub async fn activate(&self, activated_by: &str) -> Result<(), KillSwitchError> {
        // Use compare_exchange to atomically check and set
        let was_inactive = self
            .active
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok();

        if !was_inactive {
            warn!(
                activated_by = %activated_by,
                "Attempted to activate kill switch that is already active"
            );
            return Err(KillSwitchError::AlreadyActive);
        }

        let now = Utc::now();

        // Update metadata
        {
            let mut at = self.activated_at.write().await;
            *at = Some(now);
        }
        {
            let mut by = self.activated_by.write().await;
            *by = Some(activated_by.to_string());
        }

        // Broadcast the event
        let event = KillSwitchEvent::Activated {
            by: activated_by.to_string(),
            at: now,
        };
        // Ignore send errors (no receivers)
        let _ = self.sender.send(event);

        error!(
            activated_by = %activated_by,
            activated_at = %now,
            "KILL SWITCH ACTIVATED - All automation halted"
        );

        Ok(())
    }

    /// Deactivates the kill switch, allowing automation to resume.
    ///
    /// # Arguments
    ///
    /// * `deactivated_by` - Identifier of who is deactivating the kill switch.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the kill switch was successfully deactivated,
    /// or `Err(KillSwitchError::NotActive)` if it was not active.
    pub async fn deactivate(&self, deactivated_by: &str) -> Result<(), KillSwitchError> {
        // Use compare_exchange to atomically check and set
        let was_active = self
            .active
            .compare_exchange(true, false, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok();

        if !was_active {
            warn!(
                deactivated_by = %deactivated_by,
                "Attempted to deactivate kill switch that is not active"
            );
            return Err(KillSwitchError::NotActive);
        }

        let now = Utc::now();

        // Get previous activation info for logging
        let previous_by = {
            let by = self.activated_by.read().await;
            by.clone()
        };
        let previous_at = {
            let at = self.activated_at.read().await;
            *at
        };

        // Clear metadata
        {
            let mut at = self.activated_at.write().await;
            *at = None;
        }
        {
            let mut by = self.activated_by.write().await;
            *by = None;
        }

        // Broadcast the event
        let event = KillSwitchEvent::Deactivated {
            by: deactivated_by.to_string(),
            at: now,
        };
        // Ignore send errors (no receivers)
        let _ = self.sender.send(event);

        info!(
            deactivated_by = %deactivated_by,
            deactivated_at = %now,
            previous_activated_by = ?previous_by,
            previous_activated_at = ?previous_at,
            "Kill switch deactivated - Automation may resume"
        );

        Ok(())
    }

    /// Checks if the kill switch is currently active.
    ///
    /// This is a fast, lock-free check using atomic operations.
    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::SeqCst)
    }

    /// Checks if automation can proceed.
    ///
    /// This method is designed for use with the `?` operator to provide
    /// a convenient way to bail out of automated actions when the kill
    /// switch is engaged.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the kill switch is not active (automation can proceed),
    /// or `Err(KillSwitchActive)` if the kill switch is active.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tw_policy::kill_switch::{KillSwitch, KillSwitchActive};
    ///
    /// async fn perform_automated_action(kill_switch: &KillSwitch) -> Result<(), KillSwitchActive> {
    ///     kill_switch.check()?;
    ///     // Proceed with action...
    ///     Ok(())
    /// }
    /// ```
    pub fn check(&self) -> Result<(), KillSwitchActive> {
        if self.is_active() {
            // We need to block to get the metadata, but check() should be fast
            // For a truly non-blocking check, use is_active() directly
            // This is a trade-off for better error messages
            Err(KillSwitchActive {
                activated_at: Utc::now(), // Approximation when we can't access async
                activated_by: "unknown".to_string(),
            })
        } else {
            Ok(())
        }
    }

    /// Checks if automation can proceed, with full metadata in errors.
    ///
    /// This is the async version of `check()` that provides accurate
    /// activation metadata in the error.
    pub async fn check_async(&self) -> Result<(), KillSwitchActive> {
        if self.is_active() {
            let activated_at = {
                let at = self.activated_at.read().await;
                at.unwrap_or_else(Utc::now)
            };
            let activated_by = {
                let by = self.activated_by.read().await;
                by.clone().unwrap_or_else(|| "unknown".to_string())
            };
            Err(KillSwitchActive {
                activated_at,
                activated_by,
            })
        } else {
            Ok(())
        }
    }

    /// Subscribes to kill switch events.
    ///
    /// Returns a receiver that will receive all future kill switch events.
    /// Note that events sent before subscribing will not be received.
    pub fn subscribe(&self) -> broadcast::Receiver<KillSwitchEvent> {
        self.sender.subscribe()
    }

    /// Returns the current status of the kill switch.
    pub async fn status(&self) -> KillSwitchStatus {
        let active = self.is_active();
        let activated_at = {
            let at = self.activated_at.read().await;
            *at
        };
        let activated_by = {
            let by = self.activated_by.read().await;
            by.clone()
        };

        KillSwitchStatus {
            active,
            activated_at,
            activated_by,
        }
    }
}

impl Default for KillSwitch {
    fn default() -> Self {
        Self::new()
    }
}

// KillSwitch is Send + Sync due to its use of atomic operations and RwLock
unsafe impl Send for KillSwitch {}
unsafe impl Sync for KillSwitch {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::time::{sleep, Duration};

    #[tokio::test]
    async fn test_new_kill_switch_is_inactive() {
        let ks = KillSwitch::new();
        assert!(!ks.is_active());
        assert!(ks.check().is_ok());
    }

    #[tokio::test]
    async fn test_activate_and_deactivate() {
        let ks = KillSwitch::new();

        // Activate
        ks.activate("admin").await.unwrap();
        assert!(ks.is_active());
        assert!(ks.check().is_err());

        // Deactivate
        ks.deactivate("admin").await.unwrap();
        assert!(!ks.is_active());
        assert!(ks.check().is_ok());
    }

    #[tokio::test]
    async fn test_double_activate_fails() {
        let ks = KillSwitch::new();

        ks.activate("admin1").await.unwrap();
        let result = ks.activate("admin2").await;

        assert!(matches!(result, Err(KillSwitchError::AlreadyActive)));
    }

    #[tokio::test]
    async fn test_double_deactivate_fails() {
        let ks = KillSwitch::new();

        let result = ks.deactivate("admin").await;
        assert!(matches!(result, Err(KillSwitchError::NotActive)));

        ks.activate("admin").await.unwrap();
        ks.deactivate("admin").await.unwrap();

        let result = ks.deactivate("admin").await;
        assert!(matches!(result, Err(KillSwitchError::NotActive)));
    }

    #[tokio::test]
    async fn test_status() {
        let ks = KillSwitch::new();

        // Initially inactive
        let status = ks.status().await;
        assert!(!status.active);
        assert!(status.activated_at.is_none());
        assert!(status.activated_by.is_none());

        // After activation
        ks.activate("security_admin").await.unwrap();
        let status = ks.status().await;
        assert!(status.active);
        assert!(status.activated_at.is_some());
        assert_eq!(status.activated_by, Some("security_admin".to_string()));

        // After deactivation
        ks.deactivate("security_admin").await.unwrap();
        let status = ks.status().await;
        assert!(!status.active);
        assert!(status.activated_at.is_none());
        assert!(status.activated_by.is_none());
    }

    #[tokio::test]
    async fn test_check_async() {
        let ks = KillSwitch::new();

        assert!(ks.check_async().await.is_ok());

        ks.activate("admin").await.unwrap();

        let err = ks.check_async().await.unwrap_err();
        assert_eq!(err.activated_by, "admin");
    }

    #[tokio::test]
    async fn test_subscribe_receives_events() {
        let ks = KillSwitch::new();
        let mut rx = ks.subscribe();

        ks.activate("admin").await.unwrap();

        let event = rx.recv().await.unwrap();
        match event {
            KillSwitchEvent::Activated { by, .. } => {
                assert_eq!(by, "admin");
            }
            _ => panic!("Expected Activated event"),
        }

        ks.deactivate("admin").await.unwrap();

        let event = rx.recv().await.unwrap();
        match event {
            KillSwitchEvent::Deactivated { by, .. } => {
                assert_eq!(by, "admin");
            }
            _ => panic!("Expected Deactivated event"),
        }
    }

    #[tokio::test]
    async fn test_concurrent_access() {
        let ks = Arc::new(KillSwitch::new());

        // Spawn multiple tasks that try to activate
        let mut handles = vec![];

        for i in 0..10 {
            let ks = Arc::clone(&ks);
            handles.push(tokio::spawn(async move {
                ks.activate(&format!("admin{}", i)).await
            }));
        }

        // Wait for all tasks and collect results
        let mut results = Vec::new();
        for handle in handles {
            results.push(handle.await.unwrap());
        }

        // Exactly one should succeed
        let successes = results.iter().filter(|r| r.is_ok()).count();
        let failures = results
            .iter()
            .filter(|r| matches!(r, Err(KillSwitchError::AlreadyActive)))
            .count();

        assert_eq!(successes, 1);
        assert_eq!(failures, 9);
        assert!(ks.is_active());
    }

    #[tokio::test]
    async fn test_concurrent_activate_deactivate() {
        let ks = Arc::new(KillSwitch::new());

        // Run multiple activation/deactivation cycles concurrently
        let mut handles = vec![];

        for i in 0..5 {
            let ks = Arc::clone(&ks);
            handles.push(tokio::spawn(async move {
                let admin = format!("admin{}", i);
                for _ in 0..10 {
                    let _ = ks.activate(&admin).await;
                    sleep(Duration::from_micros(100)).await;
                    let _ = ks.deactivate(&admin).await;
                    sleep(Duration::from_micros(100)).await;
                }
            }));
        }

        // Also spawn readers
        for _ in 0..5 {
            let ks = Arc::clone(&ks);
            handles.push(tokio::spawn(async move {
                for _ in 0..100 {
                    let _ = ks.is_active();
                    let _ = ks.check();
                    sleep(Duration::from_micros(50)).await;
                }
            }));
        }

        // Wait for all tasks to complete
        for handle in handles {
            handle.await.unwrap();
        }

        // Kill switch should be in a consistent state
        let status = ks.status().await;
        // active and metadata should be consistent
        if status.active {
            assert!(status.activated_at.is_some());
            assert!(status.activated_by.is_some());
        } else {
            assert!(status.activated_at.is_none());
            assert!(status.activated_by.is_none());
        }
    }

    #[tokio::test]
    async fn test_check_error_message() {
        let ks = KillSwitch::new();
        ks.activate("emergency_responder").await.unwrap();

        let err = ks.check_async().await.unwrap_err();
        let msg = format!("{}", err);

        assert!(msg.contains("Kill switch is active"));
        assert!(msg.contains("emergency_responder"));
    }

    #[tokio::test]
    async fn test_default_impl() {
        let ks = KillSwitch::default();
        assert!(!ks.is_active());
    }

    #[tokio::test]
    async fn test_multiple_subscribers() {
        let ks = KillSwitch::new();
        let mut rx1 = ks.subscribe();
        let mut rx2 = ks.subscribe();

        ks.activate("admin").await.unwrap();

        // Both subscribers should receive the event
        let event1 = rx1.recv().await.unwrap();
        let event2 = rx2.recv().await.unwrap();

        match (event1, event2) {
            (
                KillSwitchEvent::Activated { by: by1, .. },
                KillSwitchEvent::Activated { by: by2, .. },
            ) => {
                assert_eq!(by1, "admin");
                assert_eq!(by2, "admin");
            }
            _ => panic!("Expected Activated events"),
        }
    }
}
