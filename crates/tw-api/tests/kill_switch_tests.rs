//! Kill switch integration tests.
//!
//! These tests verify that the emergency kill switch safety control works correctly:
//! - Kill switch immediately stops all operations
//! - Concurrent access is handled safely
//! - Event subscriptions work correctly
//! - State consistency is maintained
//!
//! These tests use the kill switch implementation from tw-policy.

use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;

use tw_policy::kill_switch::{KillSwitch, KillSwitchError, KillSwitchEvent};

// =============================================================================
// Kill Switch Immediate Effect Tests
// =============================================================================

#[tokio::test]
async fn test_kill_switch_immediate_check_effect() {
    let ks = KillSwitch::new();

    // Initially, check should succeed
    assert!(
        ks.check().is_ok(),
        "Check should succeed when kill switch is inactive"
    );
    assert!(!ks.is_active(), "Kill switch should start inactive");

    // Activate the kill switch
    ks.activate("emergency_admin").await.unwrap();

    // Check should immediately fail
    assert!(
        ks.check().is_err(),
        "Check should fail immediately after activation"
    );
    assert!(ks.is_active(), "Kill switch should be active");

    // Verify error message contains useful information
    let err = ks.check_async().await.unwrap_err();
    assert!(
        err.to_string().contains("emergency_admin"),
        "Error should contain activator info"
    );
}

#[tokio::test]
async fn test_kill_switch_blocks_all_subsequent_checks() {
    let ks = KillSwitch::new();

    ks.activate("security_team").await.unwrap();

    // Multiple checks should all fail
    for _ in 0..100 {
        assert!(
            ks.check().is_err(),
            "All checks should fail after activation"
        );
    }
}

#[tokio::test]
async fn test_kill_switch_deactivation_restores_operations() {
    let ks = KillSwitch::new();

    // Activate
    ks.activate("admin").await.unwrap();
    assert!(ks.check().is_err());

    // Deactivate
    ks.deactivate("admin").await.unwrap();

    // Operations should resume
    assert!(
        ks.check().is_ok(),
        "Operations should resume after deactivation"
    );
    assert!(!ks.is_active(), "Kill switch should be inactive");
}

#[tokio::test]
async fn test_kill_switch_status_accuracy() {
    let ks = KillSwitch::new();

    // Check initial status
    let status = ks.status().await;
    assert!(!status.active);
    assert!(status.activated_at.is_none());
    assert!(status.activated_by.is_none());

    // Activate and check status
    ks.activate("incident_response").await.unwrap();

    let status = ks.status().await;
    assert!(status.active);
    assert!(status.activated_at.is_some());
    assert_eq!(status.activated_by, Some("incident_response".to_string()));

    // Deactivate and check status
    ks.deactivate("incident_response").await.unwrap();

    let status = ks.status().await;
    assert!(!status.active);
    assert!(status.activated_at.is_none());
    assert!(status.activated_by.is_none());
}

// =============================================================================
// Atomicity and Idempotency Tests
// =============================================================================

#[tokio::test]
async fn test_kill_switch_double_activation_fails() {
    let ks = KillSwitch::new();

    // First activation succeeds
    assert!(ks.activate("admin1").await.is_ok());

    // Second activation fails
    let result = ks.activate("admin2").await;
    assert_eq!(
        result,
        Err(KillSwitchError::AlreadyActive),
        "Double activation should fail"
    );

    // Kill switch should still be active (from first activation)
    assert!(ks.is_active());

    // Original activator info should be preserved
    let status = ks.status().await;
    assert_eq!(status.activated_by, Some("admin1".to_string()));
}

#[tokio::test]
async fn test_kill_switch_double_deactivation_fails() {
    let ks = KillSwitch::new();

    // Deactivating when not active should fail
    assert_eq!(
        ks.deactivate("admin").await,
        Err(KillSwitchError::NotActive),
        "Deactivating inactive switch should fail"
    );

    // Activate then deactivate twice
    ks.activate("admin").await.unwrap();
    ks.deactivate("admin").await.unwrap();

    assert_eq!(
        ks.deactivate("admin").await,
        Err(KillSwitchError::NotActive),
        "Double deactivation should fail"
    );
}

// =============================================================================
// Concurrent Access Tests
// =============================================================================

#[tokio::test]
async fn test_kill_switch_concurrent_activation_race() {
    let ks = Arc::new(KillSwitch::new());
    let mut handles = vec![];

    // Spawn 10 tasks all trying to activate simultaneously
    for i in 0..10 {
        let ks = Arc::clone(&ks);
        handles.push(tokio::spawn(async move {
            ks.activate(&format!("admin_{}", i)).await
        }));
    }

    // Collect results
    let mut results = vec![];
    for handle in handles {
        results.push(handle.await.unwrap());
    }

    // Exactly one should succeed, rest should fail
    let successes = results.iter().filter(|r| r.is_ok()).count();
    let failures = results
        .iter()
        .filter(|r| matches!(r, Err(KillSwitchError::AlreadyActive)))
        .count();

    assert_eq!(successes, 1, "Exactly one activation should succeed");
    assert_eq!(failures, 9, "9 activations should fail with AlreadyActive");
    assert!(ks.is_active(), "Kill switch should be active");
}

#[tokio::test]
async fn test_kill_switch_concurrent_check_during_activation() {
    let ks = Arc::new(KillSwitch::new());
    let mut handles = vec![];

    // Spawn readers
    for _ in 0..50 {
        let ks = Arc::clone(&ks);
        handles.push(tokio::spawn(async move {
            for _ in 0..100 {
                let _ = ks.check();
                let _ = ks.is_active();
                tokio::task::yield_now().await;
            }
        }));
    }

    // Spawn activation/deactivation cycles
    for i in 0..5 {
        let ks = Arc::clone(&ks);
        handles.push(tokio::spawn(async move {
            for j in 0..10 {
                let admin = format!("admin_{}_{}", i, j);
                let _ = ks.activate(&admin).await;
                tokio::time::sleep(Duration::from_micros(100)).await;
                let _ = ks.deactivate(&admin).await;
                tokio::time::sleep(Duration::from_micros(100)).await;
            }
        }));
    }

    // Wait for all to complete
    for handle in handles {
        handle.await.unwrap();
    }

    // State should be consistent
    let status = ks.status().await;
    if status.active {
        assert!(status.activated_at.is_some());
        assert!(status.activated_by.is_some());
    } else {
        assert!(status.activated_at.is_none());
        assert!(status.activated_by.is_none());
    }
}

#[tokio::test]
async fn test_kill_switch_high_frequency_checks() {
    let ks = Arc::new(KillSwitch::new());
    let check_count = Arc::new(std::sync::atomic::AtomicU64::new(0));

    let ks_clone = Arc::clone(&ks);
    let count_clone = Arc::clone(&check_count);

    // Background task doing rapid checks
    let checker = tokio::spawn(async move {
        for _ in 0..10000 {
            let _ = ks_clone.check();
            count_clone.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    });

    // Activate midway
    tokio::time::sleep(Duration::from_micros(100)).await;
    ks.activate("admin").await.unwrap();

    checker.await.unwrap();

    // All checks should complete
    assert_eq!(
        check_count.load(std::sync::atomic::Ordering::Relaxed),
        10000
    );
}

// =============================================================================
// Event Subscription Tests
// =============================================================================

#[tokio::test]
async fn test_kill_switch_event_subscription() {
    let ks = KillSwitch::new();
    let mut rx = ks.subscribe();

    // Activate - should receive event
    ks.activate("admin").await.unwrap();

    let event = timeout(Duration::from_secs(1), rx.recv())
        .await
        .expect("Should receive event within timeout")
        .expect("Should receive activation event");

    match event {
        KillSwitchEvent::Activated { by, at } => {
            assert_eq!(by, "admin");
            assert!(at <= chrono::Utc::now());
        }
        _ => panic!("Expected Activated event"),
    }

    // Deactivate - should receive event
    ks.deactivate("admin").await.unwrap();

    let event = timeout(Duration::from_secs(1), rx.recv())
        .await
        .expect("Should receive event within timeout")
        .expect("Should receive deactivation event");

    match event {
        KillSwitchEvent::Deactivated { by, at } => {
            assert_eq!(by, "admin");
            assert!(at <= chrono::Utc::now());
        }
        _ => panic!("Expected Deactivated event"),
    }
}

#[tokio::test]
async fn test_kill_switch_multiple_subscribers() {
    let ks = KillSwitch::new();
    let mut rx1 = ks.subscribe();
    let mut rx2 = ks.subscribe();
    let mut rx3 = ks.subscribe();

    ks.activate("admin").await.unwrap();

    // All subscribers should receive the event
    for (i, rx) in [&mut rx1, &mut rx2, &mut rx3].iter_mut().enumerate() {
        let event = timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("Should receive event")
            .expect("Subscriber should get event");

        match event {
            KillSwitchEvent::Activated { by, .. } => {
                assert_eq!(by, "admin", "Subscriber {} should receive correct event", i);
            }
            _ => panic!("Subscriber {} expected Activated event", i),
        }
    }
}

#[tokio::test]
async fn test_kill_switch_late_subscriber_misses_events() {
    let ks = KillSwitch::new();

    // Activate before subscribing
    ks.activate("admin").await.unwrap();

    // Subscribe after activation
    let mut rx = ks.subscribe();

    // Deactivate
    ks.deactivate("admin").await.unwrap();

    // Should only receive deactivation event (missed activation)
    let event = timeout(Duration::from_secs(1), rx.recv())
        .await
        .expect("Should receive event")
        .expect("Should receive deactivation event");

    match event {
        KillSwitchEvent::Deactivated { by, .. } => {
            assert_eq!(by, "admin");
        }
        KillSwitchEvent::Activated { .. } => {
            panic!("Should not receive activation event that happened before subscription");
        }
    }
}

// =============================================================================
// Check Async vs Check Sync Tests
// =============================================================================

#[tokio::test]
async fn test_check_async_provides_accurate_metadata() {
    let ks = KillSwitch::new();

    ks.activate("detailed_admin").await.unwrap();

    let err = ks.check_async().await.unwrap_err();

    assert_eq!(
        err.activated_by, "detailed_admin",
        "Async check should provide accurate activator"
    );
    // activated_at should be close to now
    let age = chrono::Utc::now() - err.activated_at;
    assert!(age.num_seconds() < 5, "Activation time should be recent");
}

#[tokio::test]
async fn test_check_sync_is_fast() {
    let ks = KillSwitch::new();
    ks.activate("admin").await.unwrap();

    let start = std::time::Instant::now();

    // Do many sync checks
    for _ in 0..10000 {
        let _ = ks.check();
    }

    let elapsed = start.elapsed();

    // Sync check should be very fast (no async overhead)
    assert!(
        elapsed.as_millis() < 100,
        "10000 sync checks should complete in < 100ms, took {:?}",
        elapsed
    );
}

// =============================================================================
// Integration Scenario Tests
// =============================================================================

#[tokio::test]
async fn test_kill_switch_automation_halt_scenario() {
    // Simulate automated tasks that check kill switch
    let ks = Arc::new(KillSwitch::new());
    let completed_tasks = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let halted_tasks = Arc::new(std::sync::atomic::AtomicU64::new(0));

    let mut handles = vec![];

    // Spawn "automation" tasks
    for _ in 0..10 {
        let ks = Arc::clone(&ks);
        let completed = Arc::clone(&completed_tasks);
        let halted = Arc::clone(&halted_tasks);

        handles.push(tokio::spawn(async move {
            for _ in 0..100 {
                // Simulate automation checking kill switch
                if ks.check().is_ok() {
                    // Automation proceeds
                    completed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    tokio::time::sleep(Duration::from_micros(100)).await;
                } else {
                    // Automation halts
                    halted.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    break;
                }
            }
        }));
    }

    // Wait a bit then activate kill switch
    tokio::time::sleep(Duration::from_millis(10)).await;
    ks.activate("security_incident").await.unwrap();

    // Wait for all tasks to complete
    for handle in handles {
        handle.await.unwrap();
    }

    // Some tasks should have been halted
    let halted = halted_tasks.load(std::sync::atomic::Ordering::Relaxed);
    assert!(halted > 0, "Some tasks should be halted by kill switch");

    // Not all iterations should have completed
    let completed = completed_tasks.load(std::sync::atomic::Ordering::Relaxed);
    assert!(
        completed < 1000, // 10 tasks * 100 iterations
        "Kill switch should prevent some work from completing"
    );
}

#[tokio::test]
async fn test_kill_switch_default_trait() {
    // Test Default trait implementation
    let ks = KillSwitch::default();
    assert!(!ks.is_active(), "Default kill switch should be inactive");
    assert!(
        ks.check().is_ok(),
        "Default kill switch should allow operations"
    );
}

#[tokio::test]
async fn test_kill_switch_across_thread_boundaries() {
    let ks = Arc::new(KillSwitch::new());

    // Activate from one thread
    let ks_activate = Arc::clone(&ks);
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            ks_activate.activate("thread_admin").await.unwrap();
        });
    })
    .join()
    .unwrap();

    // Check from another thread
    let ks_check = Arc::clone(&ks);
    let is_active = std::thread::spawn(move || ks_check.is_active())
        .join()
        .unwrap();

    assert!(
        is_active,
        "Kill switch state should be visible across threads"
    );
}
