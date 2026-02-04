//! Integration tests for multi-instance orchestrator behavior.
//!
//! These tests validate correct behavior across multiple simulated orchestrator instances,
//! including:
//! - Message distribution across consumers (no duplication, no loss)
//! - Leader election (only one instance becomes leader)
//! - Leader failover when leader releases lock
//! - Tenant isolation (no cross-tenant data access)
//! - Feature flag evaluation with tenant overrides
//! - Cache consistency across contexts
//! - Graceful shutdown behavior
//!
//! # Running these tests
//!
//! ```bash
//! cargo test --package tw-core --test multi_instance_integration_tests
//! ```
//!
//! These tests use mock implementations and do not require external services.

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::task::JoinSet;

use tw_core::cache::{Cache, DynCache, MockCache};
use tw_core::events::{EventBus, EventEnvelope, TriageEvent, TRIAGE_EVENTS_TOPIC};
use tw_core::features::{FeatureFlag, FeatureFlagStore, FeatureFlags, InMemoryFeatureFlagStore};
use tw_core::incident::{Alert, AlertSource, Severity};
use tw_core::leadership::{LeaderElector, LeaderElectorConfig, MockLeaderElector};
use tw_core::messaging::{MessageQueue, MockMessageQueue};
use tw_core::tenant::{Tenant, TenantContext};

// ============================================================================
// Test Harness: Multi-Instance Runtime Context
// ============================================================================

/// Represents a simulated orchestrator instance context.
///
/// This struct encapsulates all the distributed infrastructure components
/// that would be shared in a real multi-instance deployment.
#[allow(dead_code)]
struct OrchestratorContext {
    /// Unique identifier for this instance.
    instance_id: String,
    /// Shared message queue (simulates Redis Streams/RabbitMQ/Kafka).
    message_queue: Arc<MockMessageQueue>,
    /// Shared cache (simulates Redis cache).
    cache: Arc<MockCache>,
    /// Leader elector (shares state with other instances).
    leader_elector: MockLeaderElector,
    /// Event bus configured with distributed mode.
    event_bus: EventBus,
    /// Feature flags service.
    feature_flags: Arc<FeatureFlags>,
}

impl OrchestratorContext {
    /// Creates a new orchestrator context with the given instance ID.
    fn new(
        instance_id: &str,
        shared_queue: Arc<MockMessageQueue>,
        shared_cache: Arc<MockCache>,
        base_elector: &MockLeaderElector,
        feature_flags: Arc<FeatureFlags>,
    ) -> Self {
        // Create a leader elector that shares state with others
        let leader_elector = base_elector.create_peer(instance_id);

        // Create event bus in distributed mode
        let event_bus = EventBus::builder(1024)
            .with_message_queue(Arc::clone(&shared_queue) as Arc<dyn MessageQueue>)
            .with_feature_flags(Arc::clone(&feature_flags))
            .with_instance_id(instance_id)
            .build();

        Self {
            instance_id: instance_id.to_string(),
            message_queue: shared_queue,
            cache: shared_cache,
            leader_elector,
            event_bus,
            feature_flags,
        }
    }
}

/// Test harness for simulating multiple orchestrator instances.
struct MultiInstanceTestHarness {
    /// Shared message queue across all instances.
    shared_queue: Arc<MockMessageQueue>,
    /// Shared cache across all instances.
    shared_cache: Arc<MockCache>,
    /// Base elector that provides shared state.
    base_elector: MockLeaderElector,
    /// Feature flags service.
    feature_flags: Arc<FeatureFlags>,
    /// Created orchestrator contexts.
    instances: Vec<OrchestratorContext>,
}

impl MultiInstanceTestHarness {
    /// Creates a new test harness.
    async fn new() -> Self {
        let shared_queue = Arc::new(MockMessageQueue::new());
        let shared_cache = Arc::new(MockCache::new());
        let base_elector = MockLeaderElector::with_default_config();

        // Create feature flags with distributed_queue enabled
        let store: Arc<dyn FeatureFlagStore> = Arc::new(InMemoryFeatureFlagStore::new());
        let distributed_flag =
            FeatureFlag::new("distributed_queue", "Enable distributed queue", true, None).unwrap();
        store.upsert(&distributed_flag).await.unwrap();

        let feature_flags = Arc::new(FeatureFlags::new(store));
        feature_flags.refresh().await.unwrap();

        Self {
            shared_queue,
            shared_cache,
            base_elector,
            feature_flags,
            instances: Vec::new(),
        }
    }

    /// Creates and returns a new orchestrator context.
    fn create_instance(&mut self, instance_id: &str) -> &OrchestratorContext {
        let ctx = OrchestratorContext::new(
            instance_id,
            Arc::clone(&self.shared_queue),
            Arc::clone(&self.shared_cache),
            &self.base_elector,
            Arc::clone(&self.feature_flags),
        );
        self.instances.push(ctx);
        self.instances.last().unwrap()
    }

    /// Gets a reference to an instance by index.
    fn get_instance(&self, index: usize) -> Option<&OrchestratorContext> {
        self.instances.get(index)
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

fn create_test_alert(id: &str) -> Alert {
    Alert {
        id: id.to_string(),
        source: AlertSource::Siem("TestSiem".to_string()),
        alert_type: "test".to_string(),
        severity: Severity::Medium,
        title: format!("Test Alert {}", id),
        description: Some("Test alert for integration testing".to_string()),
        data: serde_json::json!({"test_id": id}),
        timestamp: chrono::Utc::now(),
        tags: vec!["test".to_string()],
    }
}

fn create_tenant(slug: &str) -> Tenant {
    Tenant::new(slug, &format!("{} Organization", slug)).expect("Valid slug")
}

// ============================================================================
// TEST: Message Distribution Across Consumers
// ============================================================================

/// Tests that messages are distributed to all subscriber groups without duplication or loss.
///
/// In the mock implementation, all subscribers in the same topic receive all messages
/// (broadcast semantics). This test verifies that behavior is consistent.
#[tokio::test]
async fn test_message_distribution_no_duplication_no_loss() {
    let mut harness = MultiInstanceTestHarness::new().await;

    // Create 3 orchestrator instances
    harness.create_instance("instance-1");
    harness.create_instance("instance-2");
    harness.create_instance("instance-3");

    let queue = Arc::clone(&harness.shared_queue);

    // Create subscriptions for each instance (different consumer groups)
    let sub1 = queue
        .subscribe(TRIAGE_EVENTS_TOPIC, "tw-orchestrator-instance-1")
        .await
        .unwrap();
    let sub2 = queue
        .subscribe(TRIAGE_EVENTS_TOPIC, "tw-orchestrator-instance-2")
        .await
        .unwrap();
    let sub3 = queue
        .subscribe(TRIAGE_EVENTS_TOPIC, "tw-orchestrator-instance-3")
        .await
        .unwrap();

    // Give subscriptions time to set up
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Publish 10 events through the first instance's event bus
    let instance = harness.get_instance(0).unwrap();

    for i in 0..10 {
        let alert = create_test_alert(&format!("dist-test-{}", i));
        let event = TriageEvent::AlertReceived(alert);
        instance.event_bus.publish(event).await.unwrap();
    }

    // Collect messages from each subscriber
    let timeout = Duration::from_secs(2);

    let collect_messages = |mut sub: tw_core::messaging::Subscription, count: usize| async move {
        let mut received = Vec::new();
        for _ in 0..count {
            match tokio::time::timeout(timeout, sub.recv()).await {
                Ok(Some(msg)) => received.push(msg),
                _ => break,
            }
        }
        received
    };

    let (msgs1, msgs2, msgs3) = tokio::join!(
        collect_messages(sub1, 10),
        collect_messages(sub2, 10),
        collect_messages(sub3, 10),
    );

    // All subscribers should receive all 10 messages (broadcast semantics in mock)
    assert_eq!(msgs1.len(), 10, "Subscriber 1 should receive all messages");
    assert_eq!(msgs2.len(), 10, "Subscriber 2 should receive all messages");
    assert_eq!(msgs3.len(), 10, "Subscriber 3 should receive all messages");

    // Verify no duplicate message IDs within a single subscriber
    let ids1: HashSet<_> = msgs1.iter().map(|m| m.id.clone()).collect();
    assert_eq!(ids1.len(), 10, "No duplicates in subscriber 1");

    let ids2: HashSet<_> = msgs2.iter().map(|m| m.id.clone()).collect();
    assert_eq!(ids2.len(), 10, "No duplicates in subscriber 2");

    // Verify message content is valid EventEnvelope
    for msg in &msgs1 {
        let envelope = EventEnvelope::from_bytes(&msg.payload).expect("Valid envelope");
        assert_eq!(envelope.event.event_type(), "alert_received");
    }
}

/// Tests that messages published by different instances are received by all subscribers.
#[tokio::test]
async fn test_message_distribution_from_multiple_publishers() {
    let shared_queue = Arc::new(MockMessageQueue::new());

    // Create 3 event buses (simulating 3 orchestrator instances)
    let event_bus_1 = EventBus::builder(512)
        .with_message_queue(Arc::clone(&shared_queue) as Arc<dyn MessageQueue>)
        .with_instance_id("publisher-1")
        .build();

    let event_bus_2 = EventBus::builder(512)
        .with_message_queue(Arc::clone(&shared_queue) as Arc<dyn MessageQueue>)
        .with_instance_id("publisher-2")
        .build();

    let event_bus_3 = EventBus::builder(512)
        .with_message_queue(Arc::clone(&shared_queue) as Arc<dyn MessageQueue>)
        .with_instance_id("publisher-3")
        .build();

    // Subscribe before publishing
    let mut subscription = shared_queue
        .subscribe(TRIAGE_EVENTS_TOPIC, "consumer-group")
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Each publisher publishes 5 events
    for i in 0..5 {
        let alert1 = create_test_alert(&format!("pub1-{}", i));
        event_bus_1
            .publish(TriageEvent::AlertReceived(alert1))
            .await
            .unwrap();

        let alert2 = create_test_alert(&format!("pub2-{}", i));
        event_bus_2
            .publish(TriageEvent::AlertReceived(alert2))
            .await
            .unwrap();

        let alert3 = create_test_alert(&format!("pub3-{}", i));
        event_bus_3
            .publish(TriageEvent::AlertReceived(alert3))
            .await
            .unwrap();
    }

    // Collect all 15 messages
    let timeout = Duration::from_secs(2);
    let mut received = Vec::new();
    for _ in 0..15 {
        match tokio::time::timeout(timeout, subscription.recv()).await {
            Ok(Some(msg)) => {
                let envelope = EventEnvelope::from_bytes(&msg.payload).unwrap();
                received.push(envelope);
            }
            _ => break,
        }
    }

    assert_eq!(received.len(), 15, "Should receive all 15 messages");

    // Verify messages came from different sources
    let sources: HashSet<_> = received
        .iter()
        .filter_map(|e| e.source_instance.clone())
        .collect();
    assert_eq!(
        sources.len(),
        3,
        "Messages should come from 3 different publishers"
    );
    assert!(sources.contains("publisher-1"));
    assert!(sources.contains("publisher-2"));
    assert!(sources.contains("publisher-3"));
}

// ============================================================================
// TEST: Leader Election - Only One Instance Becomes Leader
// ============================================================================

/// Tests that only one instance can become leader for a given resource.
#[tokio::test]
async fn test_leader_election_only_one_leader() {
    let mut harness = MultiInstanceTestHarness::new().await;

    // Create 5 orchestrator instances
    for i in 0..5 {
        harness.create_instance(&format!("elector-{}", i));
    }

    let ttl = Duration::from_secs(30);
    let resource = "tw-orchestrator-scheduler";

    // All instances try to acquire leadership concurrently
    let mut tasks = JoinSet::new();

    for i in 0..5 {
        let instance = harness.get_instance(i).unwrap();
        let elector = instance.leader_elector.clone();

        tasks.spawn(async move { elector.try_acquire(resource, ttl).await });
    }

    // Collect results
    let mut leaders = Vec::new();
    let mut non_leaders = 0;

    while let Some(result) = tasks.join_next().await {
        let lease_result = result.expect("Task should complete");
        match lease_result {
            Ok(Some(lease)) => leaders.push(lease),
            Ok(None) => non_leaders += 1,
            Err(e) => panic!("Unexpected error: {}", e),
        }
    }

    // Exactly one leader should be elected
    assert_eq!(
        leaders.len(),
        1,
        "Exactly one instance should become leader, got {}",
        leaders.len()
    );
    assert_eq!(non_leaders, 4, "4 instances should not be leaders");

    // The leader should have fencing token 1
    assert_eq!(
        leaders[0].fencing_token, 1,
        "First leader should have token 1"
    );
}

/// Tests that leader check methods work correctly.
#[tokio::test]
async fn test_leader_election_is_leader_check() {
    let elector1 = MockLeaderElector::new(LeaderElectorConfig::new("instance-1"));
    let elector2 = elector1.create_peer("instance-2");

    let resource = "test-resource";

    // Neither is leader initially
    assert!(!elector1.is_leader(resource));
    assert!(!elector2.is_leader(resource));

    // Instance 1 acquires leadership
    let lease = elector1
        .try_acquire(resource, Duration::from_secs(30))
        .await
        .unwrap()
        .expect("Should acquire");

    // Instance 1 is leader, instance 2 is not
    assert!(elector1.is_leader(resource));
    assert!(!elector2.is_leader(resource));

    // get_leader should return instance 1
    let leader_info = elector2.get_leader(resource).await.unwrap();
    assert!(leader_info.is_some());
    assert_eq!(leader_info.unwrap().holder_id, "instance-1");

    // Release and verify
    elector1.release(&lease).await.unwrap();
    assert!(!elector1.is_leader(resource));
}

// ============================================================================
// TEST: Leader Failover When Leader Releases Lock
// ============================================================================

/// Tests that another instance can become leader when the current leader releases.
#[tokio::test]
async fn test_leader_failover_on_release() {
    let elector1 = MockLeaderElector::new(LeaderElectorConfig::new("primary"));
    let elector2 = elector1.create_peer("standby");

    let resource = "failover-resource";
    let ttl = Duration::from_secs(30);

    // Primary acquires leadership
    let lease1 = elector1
        .try_acquire(resource, ttl)
        .await
        .unwrap()
        .expect("Primary should acquire");

    assert_eq!(lease1.holder_id, "primary");
    assert_eq!(lease1.fencing_token, 1);

    // Standby cannot acquire
    let result = elector2.try_acquire(resource, ttl).await.unwrap();
    assert!(
        result.is_none(),
        "Standby should not be able to acquire while primary holds"
    );

    // Primary releases
    elector1.release(&lease1).await.unwrap();

    // Standby can now acquire
    let lease2 = elector2
        .try_acquire(resource, ttl)
        .await
        .unwrap()
        .expect("Standby should acquire after release");

    assert_eq!(lease2.holder_id, "standby");
    assert_eq!(lease2.fencing_token, 2, "Fencing token should increment");
}

/// Tests leader failover when the lease expires.
#[tokio::test]
async fn test_leader_failover_on_expiration() {
    let elector1 = MockLeaderElector::new(LeaderElectorConfig::new("original-leader"));
    let elector2 = elector1.create_peer("new-leader");

    let resource = "expiring-resource";

    // Original leader acquires with short TTL
    let _lease1 = elector1
        .try_acquire(resource, Duration::from_secs(1))
        .await
        .unwrap()
        .expect("Should acquire");

    // New leader cannot acquire yet
    let result = elector2
        .try_acquire(resource, Duration::from_secs(30))
        .await
        .unwrap();
    assert!(result.is_none());

    // Advance time past expiration
    elector1.advance_time(Duration::from_secs(5)).await;

    // New leader can now acquire
    let lease2 = elector2
        .try_acquire(resource, Duration::from_secs(30))
        .await
        .unwrap()
        .expect("Should acquire after expiration");

    assert_eq!(lease2.holder_id, "new-leader");
    assert_eq!(lease2.fencing_token, 2);
}

/// Tests that lease renewal keeps leadership.
#[tokio::test]
async fn test_leader_lease_renewal() {
    let elector = MockLeaderElector::new(LeaderElectorConfig::new("renewing-leader"));

    let resource = "renewal-resource";

    // Acquire leadership
    let mut lease = elector
        .try_acquire(resource, Duration::from_secs(10))
        .await
        .unwrap()
        .expect("Should acquire");

    let original_expiry = lease.expires_at;

    // Advance time a bit (but not past expiry)
    elector.advance_time(Duration::from_secs(5)).await;

    // Renew the lease
    let renewed = elector.renew(&mut lease).await.unwrap();
    assert!(renewed, "Renewal should succeed");
    assert!(
        lease.expires_at > original_expiry,
        "Expiry should be extended"
    );

    // Should still be leader
    assert!(elector.is_leader(resource));
}

// ============================================================================
// TEST: Tenant Isolation - No Cross-Tenant Data Access
// ============================================================================

/// Tests that cache namespacing provides tenant isolation.
#[tokio::test]
async fn test_tenant_isolation_cache_namespacing() {
    // Create caches with different namespaces (simulating per-tenant isolation)
    let tenant_a_cache = MockCache::with_namespace("tenant-alpha");
    let tenant_b_cache = MockCache::with_namespace("tenant-beta");

    // Set the same key in both caches with different values
    tenant_a_cache
        .set("shared_key", b"tenant-a-value", Duration::from_secs(60))
        .await
        .unwrap();

    tenant_b_cache
        .set("shared_key", b"tenant-b-value", Duration::from_secs(60))
        .await
        .unwrap();

    // Each tenant should see their own value
    let value_a = tenant_a_cache.get("shared_key").await.unwrap();
    let value_b = tenant_b_cache.get("shared_key").await.unwrap();

    assert_eq!(value_a, Some(b"tenant-a-value".to_vec()));
    assert_eq!(value_b, Some(b"tenant-b-value".to_vec()));

    // Verify they don't see each other's data
    // (Different namespaces = different full keys internally)
}

/// Tests that tenant contexts maintain proper isolation.
#[tokio::test]
async fn test_tenant_context_isolation() {
    let tenant_a = create_tenant("tenant-alpha");
    let tenant_b = create_tenant("tenant-beta");

    let ctx_a = TenantContext::from_tenant(&tenant_a);
    let ctx_b = TenantContext::from_tenant(&tenant_b);

    // Verify contexts are independent
    assert_ne!(ctx_a.tenant_id, ctx_b.tenant_id);
    assert_ne!(ctx_a.tenant_slug, ctx_b.tenant_slug);

    // Settings are independent
    assert!(Arc::ptr_eq(&ctx_a.settings, &ctx_a.settings));
    assert!(!Arc::ptr_eq(&ctx_a.settings, &ctx_b.settings));
}

/// Tests that messages include tenant context for filtering.
#[tokio::test]
async fn test_tenant_isolation_event_source_tracking() {
    let shared_queue = Arc::new(MockMessageQueue::new());

    // Create event buses for different tenants
    let tenant_a_bus = EventBus::builder(512)
        .with_message_queue(Arc::clone(&shared_queue) as Arc<dyn MessageQueue>)
        .with_instance_id("tenant-alpha-instance")
        .build();

    let tenant_b_bus = EventBus::builder(512)
        .with_message_queue(Arc::clone(&shared_queue) as Arc<dyn MessageQueue>)
        .with_instance_id("tenant-beta-instance")
        .build();

    // Subscribe to receive all messages
    let mut subscription = shared_queue
        .subscribe(TRIAGE_EVENTS_TOPIC, "all-tenants")
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Each tenant publishes an event
    let alert_a = create_test_alert("tenant-a-alert");
    tenant_a_bus
        .publish(TriageEvent::AlertReceived(alert_a))
        .await
        .unwrap();

    let alert_b = create_test_alert("tenant-b-alert");
    tenant_b_bus
        .publish(TriageEvent::AlertReceived(alert_b))
        .await
        .unwrap();

    // Receive both messages
    let timeout = Duration::from_secs(1);
    let mut received = Vec::new();

    for _ in 0..2 {
        if let Ok(Some(msg)) = tokio::time::timeout(timeout, subscription.recv()).await {
            let envelope = EventEnvelope::from_bytes(&msg.payload).unwrap();
            received.push(envelope);
        }
    }

    assert_eq!(received.len(), 2);

    // Verify source instances are different
    let sources: HashSet<_> = received
        .iter()
        .filter_map(|e| e.source_instance.clone())
        .collect();

    assert!(sources.contains("tenant-alpha-instance"));
    assert!(sources.contains("tenant-beta-instance"));
}

// ============================================================================
// TEST: Feature Flag Evaluation with Tenant Overrides
// ============================================================================

/// Tests that global feature flags work correctly.
#[tokio::test]
async fn test_feature_flags_global_default() {
    let store: Arc<dyn FeatureFlagStore> = Arc::new(InMemoryFeatureFlagStore::new());

    // Create flags with different defaults
    let enabled_flag =
        FeatureFlag::new("enabled_feature", "Enabled by default", true, None).unwrap();
    let disabled_flag =
        FeatureFlag::new("disabled_feature", "Disabled by default", false, None).unwrap();

    store.upsert(&enabled_flag).await.unwrap();
    store.upsert(&disabled_flag).await.unwrap();

    let flags = FeatureFlags::new(store);
    flags.refresh().await.unwrap();

    // Without tenant context, use defaults
    assert!(flags.is_enabled("enabled_feature", None));
    assert!(!flags.is_enabled("disabled_feature", None));
    assert!(!flags.is_enabled("unknown_feature", None)); // Unknown = false
}

/// Tests that per-tenant feature flag overrides work correctly.
#[tokio::test]
async fn test_feature_flags_tenant_overrides() {
    let store: Arc<dyn FeatureFlagStore> = Arc::new(InMemoryFeatureFlagStore::new());

    let tenant = create_tenant("override-tenant");
    let ctx = TenantContext::from_tenant(&tenant);

    // Create a flag that's disabled by default but enabled for this tenant
    let mut flag = FeatureFlag::new("beta_feature", "Beta feature", false, None).unwrap();
    flag.set_tenant_override(ctx.tenant_id, true);
    store.upsert(&flag).await.unwrap();

    let flags = FeatureFlags::new(store);
    flags.refresh().await.unwrap();

    // Without tenant context: disabled
    assert!(!flags.is_enabled("beta_feature", None));

    // With tenant context: enabled
    assert!(flags.is_enabled("beta_feature", Some(&ctx)));

    // Other tenant doesn't have override
    let other_tenant = create_tenant("other-tenant");
    let other_ctx = TenantContext::from_tenant(&other_tenant);
    assert!(!flags.is_enabled("beta_feature", Some(&other_ctx)));
}

/// Tests that tenant settings overrides take precedence over flag overrides.
#[tokio::test]
async fn test_feature_flags_tenant_settings_precedence() {
    let store: Arc<dyn FeatureFlagStore> = Arc::new(InMemoryFeatureFlagStore::new());

    // Create a tenant with a settings override
    let mut tenant = create_tenant("settings-tenant");
    tenant
        .settings
        .feature_overrides
        .insert("feature_x".to_string(), false); // Settings says disabled

    let ctx = TenantContext::from_tenant(&tenant);

    // Create a flag that's enabled by default AND has a tenant override to enable
    let mut flag = FeatureFlag::new("feature_x", "Feature X", true, None).unwrap();
    flag.set_tenant_override(ctx.tenant_id, true); // Flag override says enabled
    store.upsert(&flag).await.unwrap();

    let flags = FeatureFlags::new(store);
    flags.refresh().await.unwrap();

    // Tenant settings override (false) should win
    assert!(
        !flags.is_enabled("feature_x", Some(&ctx)),
        "Tenant settings override should take precedence"
    );
}

/// Tests percentage rollout with multiple tenants.
#[tokio::test]
async fn test_feature_flags_percentage_rollout() {
    let store: Arc<dyn FeatureFlagStore> = Arc::new(InMemoryFeatureFlagStore::new());

    // Create a flag with 50% rollout
    let flag = FeatureFlag::new("rollout_feature", "50% Rollout", false, Some(50)).unwrap();
    store.upsert(&flag).await.unwrap();

    let flags = FeatureFlags::new(store);
    flags.refresh().await.unwrap();

    // Test with many tenants
    let mut enabled_count = 0;
    let total_tenants = 100;

    for i in 0..total_tenants {
        let tenant = create_tenant(&format!("rollout-tenant-{}", i));
        let ctx = TenantContext::from_tenant(&tenant);

        if flags.is_enabled("rollout_feature", Some(&ctx)) {
            enabled_count += 1;
        }
    }

    // Should be roughly 50% (allow 30-70% range for small sample)
    let percentage = (enabled_count as f64 / total_tenants as f64) * 100.0;
    assert!(
        percentage > 30.0 && percentage < 70.0,
        "Expected ~50% enabled, got {}%",
        percentage
    );
}

/// Tests that percentage rollout is deterministic per tenant.
#[tokio::test]
async fn test_feature_flags_percentage_rollout_deterministic() {
    let store: Arc<dyn FeatureFlagStore> = Arc::new(InMemoryFeatureFlagStore::new());
    let flag = FeatureFlag::new("deterministic_feature", "Deterministic", false, Some(50)).unwrap();
    store.upsert(&flag).await.unwrap();

    let flags = FeatureFlags::new(store);
    flags.refresh().await.unwrap();

    let tenant = create_tenant("deterministic-tenant");
    let ctx = TenantContext::from_tenant(&tenant);

    // Check the same flag 100 times
    let first_result = flags.is_enabled("deterministic_feature", Some(&ctx));

    for _ in 0..100 {
        let result = flags.is_enabled("deterministic_feature", Some(&ctx));
        assert_eq!(
            result, first_result,
            "Percentage rollout should be deterministic"
        );
    }
}

// ============================================================================
// TEST: Cache Consistency Across Contexts
// ============================================================================

/// Tests that shared cache returns consistent values across instances.
#[tokio::test]
async fn test_cache_consistency_shared_cache() {
    let shared_cache = Arc::new(MockCache::new());

    // Simulate multiple instances using the same cache
    let cache1 = Arc::clone(&shared_cache);
    let cache2 = Arc::clone(&shared_cache);
    let cache3 = Arc::clone(&shared_cache);

    // Instance 1 sets a value
    cache1
        .set("shared_key", b"initial_value", Duration::from_secs(60))
        .await
        .unwrap();

    // All instances should see the same value
    let value1 = cache1.get("shared_key").await.unwrap();
    let value2 = cache2.get("shared_key").await.unwrap();
    let value3 = cache3.get("shared_key").await.unwrap();

    assert_eq!(value1, Some(b"initial_value".to_vec()));
    assert_eq!(value2, Some(b"initial_value".to_vec()));
    assert_eq!(value3, Some(b"initial_value".to_vec()));

    // Instance 2 updates the value
    cache2
        .set("shared_key", b"updated_value", Duration::from_secs(60))
        .await
        .unwrap();

    // All instances should see the update
    let value1 = cache1.get("shared_key").await.unwrap();
    let value3 = cache3.get("shared_key").await.unwrap();

    assert_eq!(value1, Some(b"updated_value".to_vec()));
    assert_eq!(value3, Some(b"updated_value".to_vec()));
}

/// Tests that cache get_or_set prevents thundering herd.
#[tokio::test]
async fn test_cache_consistency_get_or_set_thundering_herd() {
    let shared_cache = Arc::new(MockCache::new());
    let computation_count = Arc::new(AtomicU64::new(0));

    let mut tasks = JoinSet::new();

    // Spawn 10 concurrent tasks all trying to get_or_set the same key
    for _ in 0..10 {
        let cache = Arc::clone(&shared_cache);
        let count = Arc::clone(&computation_count);

        tasks.spawn(async move {
            cache
                .get_or_set("expensive_key", Duration::from_secs(60), || {
                    let count = Arc::clone(&count);
                    async move {
                        // Simulate expensive computation
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        count.fetch_add(1, Ordering::SeqCst);
                        Ok(b"computed_value".to_vec())
                    }
                })
                .await
        });
    }

    // Collect all results
    let mut results = Vec::new();
    while let Some(result) = tasks.join_next().await {
        results.push(result.unwrap().unwrap());
    }

    // All results should be the same
    for result in &results {
        assert_eq!(result, &b"computed_value".to_vec());
    }

    // Computation should have run only once
    let final_count = computation_count.load(Ordering::SeqCst);
    assert_eq!(
        final_count, 1,
        "Computation should run exactly once, ran {} times",
        final_count
    );
}

/// Tests cache TTL expiration.
#[tokio::test]
async fn test_cache_consistency_ttl_expiration() {
    let cache = MockCache::new();

    // Set with very short TTL
    cache
        .set("expiring_key", b"value", Duration::from_millis(50))
        .await
        .unwrap();

    // Should exist immediately
    assert!(cache.exists("expiring_key").await.unwrap());

    // Wait for expiration
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Should be expired
    let result = cache.get("expiring_key").await.unwrap();
    assert!(result.is_none(), "Key should be expired");
}

/// Tests cache batch operations.
#[tokio::test]
async fn test_cache_consistency_batch_operations() {
    let cache = MockCache::new();

    // Batch set
    let entries: Vec<(&str, &[u8], Duration)> = vec![
        ("key1", b"value1", Duration::from_secs(60)),
        ("key2", b"value2", Duration::from_secs(60)),
        ("key3", b"value3", Duration::from_secs(60)),
    ];
    cache.mset(&entries).await.unwrap();

    // Batch get
    let results = cache.mget(&["key1", "key2", "key3", "key4"]).await.unwrap();

    assert_eq!(results.len(), 4);
    assert_eq!(results[0], Some(b"value1".to_vec()));
    assert_eq!(results[1], Some(b"value2".to_vec()));
    assert_eq!(results[2], Some(b"value3".to_vec()));
    assert_eq!(results[3], None); // key4 doesn't exist
}

// ============================================================================
// TEST: Graceful Shutdown Behavior
// ============================================================================

/// Tests that leader releases lease on shutdown.
#[tokio::test]
async fn test_graceful_shutdown_leader_release() {
    let elector1 = MockLeaderElector::new(LeaderElectorConfig::new("shutting-down"));
    let elector2 = elector1.create_peer("taking-over");

    let resource = "shutdown-resource";

    // Instance 1 acquires leadership
    let lease = elector1
        .try_acquire(resource, Duration::from_secs(30))
        .await
        .unwrap()
        .expect("Should acquire");

    // Simulate graceful shutdown: release the lease
    elector1.release(&lease).await.unwrap();

    // Instance 2 can immediately take over
    let new_lease = elector2
        .try_acquire(resource, Duration::from_secs(30))
        .await
        .unwrap()
        .expect("Should acquire after shutdown");

    assert_eq!(new_lease.holder_id, "taking-over");
    assert_eq!(new_lease.fencing_token, 2);
}

/// Tests that message queue subscriptions handle shutdown gracefully.
///
/// Note: The mock implementation tracks consumer count in a spawned task,
/// which decrements the count when the task exits. The timing of task
/// cleanup is not guaranteed, so we verify the subscription was created
/// and can be dropped without issues.
#[tokio::test]
async fn test_graceful_shutdown_subscription_cleanup() {
    let queue = Arc::new(MockMessageQueue::new());

    // Create subscription
    let subscription = queue
        .subscribe("test-topic", "cleanup-group")
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Check initial consumer count
    let health1 = queue.health_check().await.unwrap();
    assert_eq!(health1.consumer_count, 1);

    // Drop the subscription (simulating shutdown)
    drop(subscription);

    // The subscription task will decrement the count when it detects
    // the channel is closed. We can verify the queue is still healthy.
    let health2 = queue.health_check().await.unwrap();
    assert!(
        health2.connected,
        "Queue should remain connected after subscription drop"
    );

    // Verify we can create new subscriptions after cleanup
    let new_subscription = queue.subscribe("test-topic", "new-group").await.unwrap();

    tokio::time::sleep(Duration::from_millis(50)).await;

    let health3 = queue.health_check().await.unwrap();
    assert!(
        health3.consumer_count >= 1,
        "New subscription should be counted"
    );

    drop(new_subscription);
}

/// Tests that cache clear works for shutdown.
#[tokio::test]
async fn test_graceful_shutdown_cache_clear() {
    let cache = MockCache::new();

    // Populate cache
    cache
        .set("key1", b"value1", Duration::from_secs(60))
        .await
        .unwrap();
    cache
        .set("key2", b"value2", Duration::from_secs(60))
        .await
        .unwrap();

    let stats_before = cache.stats().await;
    assert_eq!(stats_before.size, 2);

    // Clear on shutdown
    cache.clear().await;

    let stats_after = cache.stats().await;
    assert_eq!(stats_after.size, 0);

    // Keys should be gone
    assert!(cache.get("key1").await.unwrap().is_none());
    assert!(cache.get("key2").await.unwrap().is_none());
}

/// Tests that event bus history is preserved during shutdown.
#[tokio::test]
async fn test_graceful_shutdown_event_history_preserved() {
    let event_bus = EventBus::new(100);

    // Publish some events
    for i in 0..5 {
        let alert = create_test_alert(&format!("history-{}", i));
        event_bus
            .publish(TriageEvent::AlertReceived(alert))
            .await
            .unwrap();
    }

    // History should be preserved
    let history = event_bus.get_history(None).await;
    assert_eq!(history.len(), 5);

    // Even after getting history, it's still there
    let history2 = event_bus.get_history(Some(3)).await;
    assert_eq!(history2.len(), 3);
}

// ============================================================================
// TEST: Event Bus Metrics
// ============================================================================

/// Tests that event bus metrics are tracked correctly.
#[tokio::test]
async fn test_event_bus_metrics_tracking() {
    let queue: Arc<dyn MessageQueue> = Arc::new(MockMessageQueue::new());
    let event_bus = EventBus::builder(512)
        .with_message_queue(queue)
        .with_instance_id("metrics-test")
        .build();

    // Publish some events
    for i in 0..5 {
        let alert = create_test_alert(&format!("metrics-{}", i));
        event_bus
            .publish(TriageEvent::AlertReceived(alert))
            .await
            .unwrap();
    }

    let metrics = event_bus.metrics_snapshot();

    assert_eq!(
        metrics.events_published_broadcast, 5,
        "Should track broadcast publishes"
    );
    assert_eq!(
        metrics.events_published_queue, 5,
        "Should track queue publishes"
    );
}

/// Tests event bus distributed mode detection.
#[tokio::test]
async fn test_event_bus_distributed_mode_detection() {
    // Without queue: not distributed
    let local_bus = EventBus::new(100);
    assert!(!local_bus.is_distributed_mode());

    // With queue: distributed
    let queue: Arc<dyn MessageQueue> = Arc::new(MockMessageQueue::new());
    let distributed_bus = EventBus::builder(100)
        .with_message_queue(queue)
        .with_instance_id("distributed")
        .build();
    assert!(distributed_bus.is_distributed_mode());
}

// ============================================================================
// TEST: Multiple Resources Leadership
// ============================================================================

/// Tests that an instance can be leader for multiple resources.
#[tokio::test]
async fn test_multiple_resources_leadership() {
    let elector = MockLeaderElector::new(LeaderElectorConfig::new("multi-resource-leader"));

    let ttl = Duration::from_secs(30);

    // Acquire leadership for multiple resources
    let scheduler_lease = elector
        .try_acquire("scheduler", ttl)
        .await
        .unwrap()
        .expect("Should acquire scheduler");

    let cleanup_lease = elector
        .try_acquire("cleanup", ttl)
        .await
        .unwrap()
        .expect("Should acquire cleanup");

    let metrics_lease = elector
        .try_acquire("metrics", ttl)
        .await
        .unwrap()
        .expect("Should acquire metrics");

    // All should be acquired
    assert!(elector.is_leader("scheduler"));
    assert!(elector.is_leader("cleanup"));
    assert!(elector.is_leader("metrics"));

    // Each resource has its own fencing token counter
    assert_eq!(scheduler_lease.fencing_token, 1);
    assert_eq!(cleanup_lease.fencing_token, 1);
    assert_eq!(metrics_lease.fencing_token, 1);

    // All leases in state
    let all_leases = elector.all_leases().await;
    assert_eq!(all_leases.len(), 3);
}

// ============================================================================
// TEST: Concurrent Operations
// ============================================================================

/// Tests concurrent cache operations from multiple instances.
#[tokio::test]
async fn test_concurrent_cache_operations() {
    let shared_cache = Arc::new(MockCache::new());
    let mut tasks = JoinSet::new();

    // Spawn 20 concurrent tasks doing cache operations
    for i in 0..20 {
        let cache = Arc::clone(&shared_cache);
        tasks.spawn(async move {
            let key = format!("concurrent-{}", i % 5); // 5 keys, 4 writes each
            cache
                .set(
                    &key,
                    format!("value-{}", i).as_bytes(),
                    Duration::from_secs(60),
                )
                .await
                .unwrap();

            tokio::time::sleep(Duration::from_millis(10)).await;

            cache.get(&key).await.unwrap()
        });
    }

    // All operations should complete successfully
    let mut completed = 0;
    while let Some(result) = tasks.join_next().await {
        result.unwrap(); // Should not panic
        completed += 1;
    }

    assert_eq!(completed, 20);

    // Cache should have 5 keys
    let stats = shared_cache.stats().await;
    assert_eq!(stats.size, 5);
}

/// Tests concurrent leader election attempts.
#[tokio::test]
async fn test_concurrent_leader_election() {
    let base_elector = MockLeaderElector::new(LeaderElectorConfig::new("base"));

    let mut tasks = JoinSet::new();

    // Spawn 50 concurrent acquisition attempts
    for i in 0..50 {
        let elector = base_elector.create_peer(&format!("contender-{}", i));

        tasks.spawn(async move {
            elector
                .try_acquire("contested-resource", Duration::from_secs(30))
                .await
        });
    }

    let mut leaders = 0;
    let mut non_leaders = 0;

    while let Some(result) = tasks.join_next().await {
        match result.unwrap() {
            Ok(Some(_)) => leaders += 1,
            Ok(None) => non_leaders += 1,
            Err(e) => panic!("Unexpected error: {}", e),
        }
    }

    // Exactly one leader
    assert_eq!(leaders, 1, "Exactly one leader should be elected");
    assert_eq!(non_leaders, 49);
}
