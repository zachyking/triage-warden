//! Feature flag system for Triage Warden.
//!
//! This module provides feature flag functionality for controlling feature availability:
//! - Global defaults with per-tenant overrides
//! - Percentage-based rollouts (deterministic per tenant)
//! - In-memory caching with async refresh
//!
//! # Example
//!
//! ```rust,ignore
//! use tw_core::features::{FeatureFlags, FeatureFlag, FeatureFlagStore};
//! use tw_core::tenant::TenantContext;
//! use std::sync::Arc;
//!
//! // Create the service with a store implementation
//! let store: Arc<dyn FeatureFlagStore> = /* ... */;
//! let flags = FeatureFlags::new(store);
//!
//! // Check if a feature is enabled (sync, fast)
//! let enabled = flags.is_enabled("new_dashboard", Some(&tenant_ctx));
//!
//! // Refresh the cache from the store (async)
//! flags.refresh().await?;
//! ```

mod types;

pub use types::{FeatureFlag, FeatureFlagError, FeatureFlagStore};

use crate::tenant::TenantContext;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

/// Feature flags service with in-memory caching.
///
/// This service provides synchronous feature flag evaluation (`is_enabled`)
/// backed by an in-memory cache. The cache can be refreshed asynchronously
/// from a `FeatureFlagStore` implementation.
///
/// # Thread Safety
///
/// The service is thread-safe and can be shared across async tasks.
/// The `is_enabled` method is synchronous and non-blocking, suitable
/// for use in hot paths.
///
/// # Percentage Rollouts
///
/// Percentage rollouts are deterministic per tenant: a tenant will always
/// get the same result for a given flag. The decision is based on
/// `hash(tenant_id + flag_name) % 100 < percentage`.
pub struct FeatureFlags {
    /// In-memory cache of feature flags, keyed by flag name.
    cache: Arc<RwLock<HashMap<String, FeatureFlag>>>,

    /// Backing store for persistence.
    store: Arc<dyn FeatureFlagStore>,
}

impl FeatureFlags {
    /// Creates a new FeatureFlags service with the given store.
    pub fn new(store: Arc<dyn FeatureFlagStore>) -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
            store,
        }
    }

    /// Creates a new FeatureFlags service with pre-populated flags.
    ///
    /// This is useful for testing or when flags are loaded from configuration.
    pub fn with_flags(store: Arc<dyn FeatureFlagStore>, flags: Vec<FeatureFlag>) -> Self {
        let cache: HashMap<String, FeatureFlag> =
            flags.into_iter().map(|f| (f.name.clone(), f)).collect();

        Self {
            cache: Arc::new(RwLock::new(cache)),
            store,
        }
    }

    /// Checks if a feature flag is enabled.
    ///
    /// This method is **synchronous** and suitable for use in hot paths.
    /// It uses the in-memory cache and does not perform any async I/O.
    ///
    /// # Evaluation Order
    ///
    /// 1. **Tenant Settings Override**: If the tenant has a `feature_overrides` entry
    ///    for this flag in their settings, that value is used.
    /// 2. **Per-Tenant Override**: If the flag has a tenant-specific override, use it.
    /// 3. **Percentage Rollout**: If the flag has a percentage rollout, use
    ///    deterministic hashing to decide.
    /// 4. **Default**: Use the flag's `default_enabled` value.
    /// 5. **Unknown Flag**: If the flag is not in the cache, return `false`.
    ///
    /// # Arguments
    ///
    /// * `flag` - The feature flag name to check.
    /// * `tenant` - Optional tenant context. If None, only the default is considered.
    pub fn is_enabled(&self, flag: &str, tenant: Option<&TenantContext>) -> bool {
        // Use try_read for non-blocking access in hot paths
        // Fall back to blocking read if try_read fails (contention)
        let cache_guard = match self.cache.try_read() {
            Ok(guard) => guard,
            Err(_) => {
                // Contention - use blocking read as fallback
                // This should be rare in practice
                futures::executor::block_on(self.cache.read())
            }
        };

        let feature = match cache_guard.get(flag) {
            Some(f) => f,
            None => return false, // Unknown flag defaults to disabled
        };

        self.evaluate_flag(feature, tenant)
    }

    /// Evaluates whether a feature flag is enabled for a given tenant context.
    ///
    /// This is the core evaluation logic, separated for testing.
    fn evaluate_flag(&self, flag: &FeatureFlag, tenant: Option<&TenantContext>) -> bool {
        if let Some(ctx) = tenant {
            // 1. Check tenant settings override first
            if let Some(override_value) = ctx.get_feature_override(&flag.name) {
                return override_value;
            }

            // 2. Check per-flag tenant override
            if let Some(&override_value) = flag.tenant_overrides.get(&ctx.tenant_id) {
                return override_value;
            }

            // 3. Check percentage rollout
            if let Some(percentage) = flag.percentage_rollout {
                return self.is_in_rollout(&ctx.tenant_id, &flag.name, percentage);
            }
        }

        // 4. Return default
        flag.default_enabled
    }

    /// Determines if a tenant is in the percentage rollout for a flag.
    ///
    /// Uses deterministic hashing: `hash(tenant_id + flag_name) % 100 < percentage`
    /// This ensures:
    /// - Same tenant always gets same result for same flag
    /// - Distribution is uniform across tenants
    /// - Adding/removing tenants doesn't affect other tenants
    fn is_in_rollout(&self, tenant_id: &Uuid, flag_name: &str, percentage: u8) -> bool {
        if percentage == 0 {
            return false;
        }
        if percentage >= 100 {
            return true;
        }

        // Create deterministic hash from tenant_id + flag_name
        let mut hasher = Sha256::new();
        hasher.update(tenant_id.as_bytes());
        hasher.update(flag_name.as_bytes());
        let hash = hasher.finalize();

        // Use first 8 bytes as u64, then modulo 100
        let hash_value = u64::from_be_bytes([
            hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
        ]);

        (hash_value % 100) < percentage as u64
    }

    /// Refreshes the in-memory cache from the backing store.
    ///
    /// This method is asynchronous and should be called periodically
    /// or when flags need to be updated.
    pub async fn refresh(&self) -> Result<(), FeatureFlagError> {
        let flags = self.store.list().await?;

        let mut cache = self.cache.write().await;
        cache.clear();
        for flag in flags {
            cache.insert(flag.name.clone(), flag);
        }

        Ok(())
    }

    /// Gets a copy of a feature flag from the cache.
    pub async fn get(&self, name: &str) -> Option<FeatureFlag> {
        let cache = self.cache.read().await;
        cache.get(name).cloned()
    }

    /// Gets all feature flags from the cache.
    pub async fn list(&self) -> Vec<FeatureFlag> {
        let cache = self.cache.read().await;
        cache.values().cloned().collect()
    }

    /// Adds or updates a feature flag in both the cache and the store.
    pub async fn upsert(&self, flag: &FeatureFlag) -> Result<(), FeatureFlagError> {
        // Update store first
        self.store.upsert(flag).await?;

        // Then update cache
        let mut cache = self.cache.write().await;
        cache.insert(flag.name.clone(), flag.clone());

        Ok(())
    }

    /// Deletes a feature flag from both the cache and the store.
    pub async fn delete(&self, name: &str) -> Result<bool, FeatureFlagError> {
        // Delete from store first
        let deleted = self.store.delete(name).await?;

        // Then remove from cache
        if deleted {
            let mut cache = self.cache.write().await;
            cache.remove(name);
        }

        Ok(deleted)
    }
}

/// In-memory implementation of FeatureFlagStore for testing.
#[derive(Default)]
pub struct InMemoryFeatureFlagStore {
    flags: RwLock<HashMap<String, FeatureFlag>>,
}

impl InMemoryFeatureFlagStore {
    /// Creates a new empty in-memory store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a store with pre-populated flags.
    pub fn with_flags(flags: Vec<FeatureFlag>) -> Self {
        let map: HashMap<String, FeatureFlag> =
            flags.into_iter().map(|f| (f.name.clone(), f)).collect();
        Self {
            flags: RwLock::new(map),
        }
    }
}

#[async_trait::async_trait]
impl FeatureFlagStore for InMemoryFeatureFlagStore {
    async fn list(&self) -> Result<Vec<FeatureFlag>, FeatureFlagError> {
        let flags = self.flags.read().await;
        Ok(flags.values().cloned().collect())
    }

    async fn get(&self, name: &str) -> Result<Option<FeatureFlag>, FeatureFlagError> {
        let flags = self.flags.read().await;
        Ok(flags.get(name).cloned())
    }

    async fn upsert(&self, flag: &FeatureFlag) -> Result<(), FeatureFlagError> {
        let mut flags = self.flags.write().await;
        flags.insert(flag.name.clone(), flag.clone());
        Ok(())
    }

    async fn delete(&self, name: &str) -> Result<bool, FeatureFlagError> {
        let mut flags = self.flags.write().await;
        Ok(flags.remove(name).is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tenant::Tenant;

    fn create_test_tenant(slug: &str) -> TenantContext {
        let tenant = Tenant::new(slug, &format!("{} Org", slug)).unwrap();
        TenantContext::from_tenant(&tenant)
    }

    fn create_test_tenant_with_id(id: Uuid, slug: &str) -> TenantContext {
        // Ensure slug meets minimum length requirement (3 chars)
        let valid_slug = if slug.len() < 3 {
            format!("tenant-{}", slug)
        } else {
            slug.to_string()
        };
        let tenant = Tenant::with_id(id, &valid_slug, &format!("{} Org", slug)).unwrap();
        TenantContext::from_tenant(&tenant)
    }

    /// Helper to create a store Arc with proper trait object coercion
    fn make_store(flags: Vec<FeatureFlag>) -> Arc<dyn FeatureFlagStore> {
        Arc::new(InMemoryFeatureFlagStore::with_flags(flags))
    }

    fn make_empty_store() -> Arc<dyn FeatureFlagStore> {
        Arc::new(InMemoryFeatureFlagStore::new())
    }

    #[test]
    fn test_is_enabled_unknown_flag() {
        let store = make_empty_store();
        let flags = FeatureFlags::new(store);

        // Unknown flags default to false
        assert!(!flags.is_enabled("unknown_flag", None));
    }

    #[test]
    fn test_is_enabled_default_true() {
        let flag = FeatureFlag::new("enabled_by_default", "Test", true, None).unwrap();
        let store = make_empty_store();
        let flags = FeatureFlags::with_flags(store, vec![flag]);

        assert!(flags.is_enabled("enabled_by_default", None));
    }

    #[test]
    fn test_is_enabled_default_false() {
        let flag = FeatureFlag::new("disabled_by_default", "Test", false, None).unwrap();
        let store = make_empty_store();
        let flags = FeatureFlags::with_flags(store, vec![flag]);

        assert!(!flags.is_enabled("disabled_by_default", None));
    }

    #[test]
    fn test_is_enabled_tenant_override() {
        let tenant_ctx = create_test_tenant("test-tenant");

        let mut flag = FeatureFlag::new("feature_a", "Test", false, None).unwrap();
        flag.set_tenant_override(tenant_ctx.tenant_id, true);

        let store = make_empty_store();
        let flags = FeatureFlags::with_flags(store, vec![flag]);

        // With tenant context - should be enabled via override
        assert!(flags.is_enabled("feature_a", Some(&tenant_ctx)));

        // Without tenant context - should use default (false)
        assert!(!flags.is_enabled("feature_a", None));
    }

    #[test]
    fn test_is_enabled_tenant_settings_override_takes_precedence() {
        // Create tenant with feature override in settings
        let mut tenant = Tenant::new("priority-tenant", "Priority Tenant").unwrap();
        tenant
            .settings
            .feature_overrides
            .insert("feature_b".to_string(), false);
        let tenant_ctx = TenantContext::from_tenant(&tenant);

        // Create flag with tenant-specific override set to true
        let mut flag = FeatureFlag::new("feature_b", "Test", true, None).unwrap();
        flag.set_tenant_override(tenant_ctx.tenant_id, true); // Flag says enabled

        let store = make_empty_store();
        let flags = FeatureFlags::with_flags(store, vec![flag]);

        // Tenant settings override (false) should take precedence over flag override (true)
        assert!(!flags.is_enabled("feature_b", Some(&tenant_ctx)));
    }

    #[test]
    fn test_is_enabled_percentage_rollout_0() {
        let flag = FeatureFlag::new("rollout_0", "Test", false, Some(0)).unwrap();
        let store = make_empty_store();
        let flags = FeatureFlags::with_flags(store, vec![flag]);

        // 0% rollout - should never be enabled
        for i in 0..100 {
            let tenant = create_test_tenant(&format!("tenant-{}", i));
            assert!(!flags.is_enabled("rollout_0", Some(&tenant)));
        }
    }

    #[test]
    fn test_is_enabled_percentage_rollout_100() {
        let flag = FeatureFlag::new("rollout_100", "Test", false, Some(100)).unwrap();
        let store = make_empty_store();
        let flags = FeatureFlags::with_flags(store, vec![flag]);

        // 100% rollout - should always be enabled
        for i in 0..100 {
            let tenant = create_test_tenant(&format!("tenant-{}", i));
            assert!(flags.is_enabled("rollout_100", Some(&tenant)));
        }
    }

    #[test]
    fn test_percentage_rollout_deterministic() {
        let flag = FeatureFlag::new("rollout_50", "Test", false, Some(50)).unwrap();
        let store = make_empty_store();
        let flags = FeatureFlags::with_flags(store, vec![flag]);

        // Same tenant should always get same result
        let tenant_id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let tenant = create_test_tenant_with_id(tenant_id, "deterministic");

        let first_result = flags.is_enabled("rollout_50", Some(&tenant));

        // Check 100 times - should always be the same
        for _ in 0..100 {
            assert_eq!(
                flags.is_enabled("rollout_50", Some(&tenant)),
                first_result,
                "Percentage rollout should be deterministic"
            );
        }
    }

    #[test]
    fn test_percentage_rollout_distribution() {
        let flag = FeatureFlag::new("rollout_50", "Test", false, Some(50)).unwrap();
        let store = make_empty_store();
        let flags = FeatureFlags::with_flags(store, vec![flag]);

        // Test with many tenants - should be roughly 50% enabled
        let mut enabled_count = 0;
        let total = 1000;

        for i in 0..total {
            let tenant_id = Uuid::new_v4();
            let tenant = create_test_tenant_with_id(tenant_id, &format!("t{}", i));
            if flags.is_enabled("rollout_50", Some(&tenant)) {
                enabled_count += 1;
            }
        }

        // Allow 10% variance (400-600 out of 1000)
        let percentage = (enabled_count as f64 / total as f64) * 100.0;
        assert!(
            percentage > 40.0 && percentage < 60.0,
            "Expected ~50% enabled, got {}% ({}/{})",
            percentage,
            enabled_count,
            total
        );
    }

    #[test]
    fn test_percentage_rollout_different_flags_different_results() {
        let flag_a = FeatureFlag::new("feature_a", "Test A", false, Some(50)).unwrap();
        let flag_b = FeatureFlag::new("feature_b", "Test B", false, Some(50)).unwrap();
        let store = make_empty_store();
        let flags = FeatureFlags::with_flags(store, vec![flag_a, flag_b]);

        // A single tenant may have different results for different flags
        // (due to flag name being part of the hash)
        let mut different_count = 0;
        let total = 100;

        for i in 0..total {
            let tenant_id = Uuid::new_v4();
            let tenant = create_test_tenant_with_id(tenant_id, &format!("t{}", i));
            let a_enabled = flags.is_enabled("feature_a", Some(&tenant));
            let b_enabled = flags.is_enabled("feature_b", Some(&tenant));
            if a_enabled != b_enabled {
                different_count += 1;
            }
        }

        // Should have some tenants with different results
        assert!(
            different_count > 0,
            "Different flags should produce different rollout assignments"
        );
    }

    #[test]
    fn test_tenant_override_takes_precedence_over_percentage() {
        let tenant_ctx = create_test_tenant("override-tenant");

        // Create flag with 0% rollout but tenant override enabled
        let mut flag = FeatureFlag::new("override_test", "Test", false, Some(0)).unwrap();
        flag.set_tenant_override(tenant_ctx.tenant_id, true);

        let store = make_empty_store();
        let flags = FeatureFlags::with_flags(store, vec![flag]);

        // Tenant override should win over percentage rollout
        assert!(flags.is_enabled("override_test", Some(&tenant_ctx)));
    }

    #[tokio::test]
    async fn test_refresh_from_store() {
        let initial_flag = FeatureFlag::new("initial", "Test", true, None).unwrap();
        let store = make_store(vec![initial_flag]);
        let flags = FeatureFlags::new(Arc::clone(&store));

        // Initially cache is empty
        assert!(!flags.is_enabled("initial", None));

        // After refresh, flag should be available
        flags.refresh().await.unwrap();
        assert!(flags.is_enabled("initial", None));
    }

    #[tokio::test]
    async fn test_upsert_flag() {
        let store = make_empty_store();
        let flags = FeatureFlags::new(Arc::clone(&store));

        // Create a new flag
        let flag = FeatureFlag::new("new_flag", "New feature", true, None).unwrap();
        flags.upsert(&flag).await.unwrap();

        // Should be in cache immediately
        assert!(flags.is_enabled("new_flag", None));

        // Should also be in store
        let stored = store.get("new_flag").await.unwrap();
        assert!(stored.is_some());
        assert!(stored.unwrap().default_enabled);
    }

    #[tokio::test]
    async fn test_delete_flag() {
        let flag = FeatureFlag::new("to_delete", "Test", true, None).unwrap();
        let store = make_store(vec![flag.clone()]);
        let flags = FeatureFlags::with_flags(Arc::clone(&store), vec![flag]);

        // Initially enabled
        assert!(flags.is_enabled("to_delete", None));

        // Delete
        let deleted = flags.delete("to_delete").await.unwrap();
        assert!(deleted);

        // Should be gone from cache
        assert!(!flags.is_enabled("to_delete", None));

        // Should also be gone from store
        let stored = store.get("to_delete").await.unwrap();
        assert!(stored.is_none());
    }

    #[tokio::test]
    async fn test_delete_nonexistent_flag() {
        let store = Arc::new(InMemoryFeatureFlagStore::new());
        let flags = FeatureFlags::new(store);

        let deleted = flags.delete("nonexistent").await.unwrap();
        assert!(!deleted);
    }

    #[tokio::test]
    async fn test_get_flag() {
        let flag = FeatureFlag::new("get_test", "Test", true, Some(75)).unwrap();
        let store = Arc::new(InMemoryFeatureFlagStore::new());
        let flags = FeatureFlags::with_flags(store, vec![flag]);

        let retrieved = flags.get("get_test").await;
        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.name, "get_test");
        assert_eq!(retrieved.percentage_rollout, Some(75));
    }

    #[tokio::test]
    async fn test_list_flags() {
        let flag_a = FeatureFlag::new("flag_a", "Test A", true, None).unwrap();
        let flag_b = FeatureFlag::new("flag_b", "Test B", false, None).unwrap();
        let store = Arc::new(InMemoryFeatureFlagStore::new());
        let flags = FeatureFlags::with_flags(store, vec![flag_a, flag_b]);

        let all = flags.list().await;
        assert_eq!(all.len(), 2);

        let names: Vec<_> = all.iter().map(|f| f.name.as_str()).collect();
        assert!(names.contains(&"flag_a"));
        assert!(names.contains(&"flag_b"));
    }

    #[test]
    fn test_in_memory_store() {
        let rt = tokio::runtime::Runtime::new().unwrap();

        rt.block_on(async {
            let store = InMemoryFeatureFlagStore::new();

            // Initially empty
            let list = store.list().await.unwrap();
            assert!(list.is_empty());

            // Add a flag
            let flag = FeatureFlag::new("test", "Test", true, None).unwrap();
            store.upsert(&flag).await.unwrap();

            // Should be retrievable
            let retrieved = store.get("test").await.unwrap();
            assert!(retrieved.is_some());

            // List should have one
            let list = store.list().await.unwrap();
            assert_eq!(list.len(), 1);

            // Delete
            let deleted = store.delete("test").await.unwrap();
            assert!(deleted);

            // Should be gone
            let retrieved = store.get("test").await.unwrap();
            assert!(retrieved.is_none());
        });
    }
}
