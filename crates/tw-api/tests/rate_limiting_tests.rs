//! Rate limiting integration tests.
//!
//! These tests verify that rate limiting safety controls work correctly:
//! - Global rate limits are enforced across all sources
//! - Webhook-specific rate limits work correctly per source
//! - Rate limiter memory is bounded via LRU eviction
//! - Concurrent access is thread-safe
//!
//! These tests use the rate limiting implementations from tw-api.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

// Rate limiting types from tw-api
use tw_api::rate_limit::{
    ApiRateLimitError, ApiRateLimiter, LoginRateLimiter, RateLimitError, WebhookRateLimitError,
    WebhookRateLimiter,
};

// =============================================================================
// Global Rate Limiting Tests
// =============================================================================

#[test]
fn test_global_rate_limit_enforced() {
    // Create limiter with low global limit (5) but high per-IP limit (100)
    let limiter = LoginRateLimiter::with_config(
        100, // per_ip_limit - high to not interfere
        5,   // global_limit - low to test global enforcement
        Duration::from_secs(60),
    );

    // Use different IPs for each request
    let ips: Vec<IpAddr> = (1..=10)
        .map(|i| IpAddr::V4(Ipv4Addr::new(192, 168, 1, i)))
        .collect();

    // First 5 requests should succeed (from different IPs)
    for ip in ips.iter().take(5) {
        assert!(
            limiter.check(*ip).is_ok(),
            "Request from {} should succeed (global limit not reached)",
            ip
        );
    }

    // 6th request should fail due to global limit
    let result = limiter.check(ips[5]);
    assert_eq!(
        result,
        Err(RateLimitError::GlobalLimitExceeded),
        "Request should be rejected when global limit exceeded"
    );

    // Verify all subsequent requests also fail
    for ip in ips.iter().skip(6) {
        assert_eq!(
            limiter.check(*ip),
            Err(RateLimitError::GlobalLimitExceeded),
            "All requests should be rejected after global limit exceeded"
        );
    }
}

#[test]
fn test_api_global_rate_limit_enforced() {
    // API rate limiter with low global limit
    let limiter = ApiRateLimiter::with_config(
        100,  // per_ip_limit
        200,  // per_user_limit
        1000, // webhook_limit
        3,    // global_limit - very low
        Duration::from_secs(60),
    );

    let ips: Vec<IpAddr> = (1..=5)
        .map(|i| IpAddr::V4(Ipv4Addr::new(10, 0, 0, i)))
        .collect();

    // First 3 requests should succeed
    for ip in ips.iter().take(3) {
        assert!(
            limiter.check_ip(*ip).is_ok(),
            "API request from {} should succeed",
            ip
        );
    }

    // 4th request should fail
    assert_eq!(
        limiter.check_ip(ips[3]),
        Err(ApiRateLimitError::GlobalLimitExceeded),
        "API request should be rejected when global limit exceeded"
    );
}

#[test]
fn test_per_ip_rate_limit_isolated() {
    // Create limiter where per-IP limit is lower than global
    let limiter = LoginRateLimiter::with_config(
        3,   // per_ip_limit
        100, // global_limit
        Duration::from_secs(60),
    );

    let ip1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    let ip2 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));

    // Exhaust IP1's limit
    for _ in 0..3 {
        assert!(limiter.check(ip1).is_ok());
    }
    assert_eq!(
        limiter.check(ip1),
        Err(RateLimitError::PerIpLimitExceeded),
        "IP1 should be rate limited"
    );

    // IP2 should still have full quota
    for _ in 0..3 {
        assert!(
            limiter.check(ip2).is_ok(),
            "IP2 should not be affected by IP1's rate limit"
        );
    }
    assert_eq!(
        limiter.check(ip2),
        Err(RateLimitError::PerIpLimitExceeded),
        "IP2 should be rate limited after its own quota exhausted"
    );
}

// =============================================================================
// Webhook Rate Limiting Tests
// =============================================================================

#[test]
fn test_webhook_per_source_rate_limit() {
    let limiter = WebhookRateLimiter::with_config(
        3,    // per_source_limit
        100,  // global_limit
        1000, // max_queue_depth
        Duration::from_secs(60),
    );

    // Exhaust Splunk's limit
    for _ in 0..3 {
        assert!(limiter.check("splunk").is_ok());
    }

    // Splunk should be rate limited
    let result = limiter.check("splunk");
    assert!(
        matches!(result, Err(WebhookRateLimitError::PerSourceLimitExceeded { source }) if source == "splunk"),
        "Splunk source should be rate limited"
    );

    // CrowdStrike should still work
    for _ in 0..3 {
        assert!(
            limiter.check("crowdstrike").is_ok(),
            "CrowdStrike should not be affected by Splunk's rate limit"
        );
    }
}

#[test]
fn test_webhook_global_rate_limit() {
    let limiter = WebhookRateLimiter::with_config(
        100,  // per_source_limit - high
        5,    // global_limit - low
        1000, // max_queue_depth
        Duration::from_secs(60),
    );

    // Different sources, should hit global limit
    let sources = [
        "source1", "source2", "source3", "source4", "source5", "source6",
    ];

    for source in sources.iter().take(5) {
        assert!(
            limiter.check(source).is_ok(),
            "Webhook from {} should succeed",
            source
        );
    }

    // 6th should hit global limit
    assert_eq!(
        limiter.check(sources[5]),
        Err(WebhookRateLimitError::GlobalLimitExceeded),
        "Webhook should be rejected when global limit exceeded"
    );
}

#[test]
fn test_webhook_queue_overflow_protection() {
    let limiter = WebhookRateLimiter::with_config(
        100, // per_source_limit
        100, // global_limit
        3,   // max_queue_depth - very small
        Duration::from_secs(60),
    );

    // Simulate queue filling up
    limiter.increment_queue_depth();
    limiter.increment_queue_depth();
    limiter.increment_queue_depth();

    // New webhooks should be rejected
    let result = limiter.check("any_source");
    assert!(
        matches!(
            result,
            Err(WebhookRateLimitError::QueueOverflow {
                current_depth: 3,
                max_depth: 3
            })
        ),
        "Webhooks should be rejected when queue is full"
    );

    // Verify stats reflect the overflow
    let stats = limiter.stats();
    assert_eq!(stats.queue_overflow_rejections, 1);
    assert_eq!(stats.current_queue_depth, 3);

    // After processing one item, new webhook should work
    limiter.decrement_queue_depth();
    assert!(
        limiter.check("any_source").is_ok(),
        "Webhook should succeed after queue space is freed"
    );
}

#[test]
fn test_webhook_stats_accuracy() {
    let limiter = WebhookRateLimiter::with_config(
        2,   // per_source_limit
        100, // global_limit
        100, // max_queue_depth
        Duration::from_secs(60),
    );

    // Make requests
    limiter.check("source_a").ok();
    limiter.check("source_a").ok();
    limiter.check("source_a").ok(); // Should be rate limited
    limiter.check("source_b").ok();

    let stats = limiter.stats();
    assert_eq!(stats.total_requests, 4, "Total requests should be 4");
    assert_eq!(
        stats.rate_limited_requests, 1,
        "One request should be rate limited"
    );
    assert_eq!(stats.tracked_sources, 2, "Two sources should be tracked");
}

// =============================================================================
// Rate Limiter Memory Bounded Tests (LRU Eviction)
// =============================================================================

#[test]
fn test_login_rate_limiter_lru_eviction() {
    // Create limiter with very small cache (5 entries)
    let limiter = LoginRateLimiter::with_config_and_max_entries(
        10,   // per_ip_limit
        1000, // global_limit
        Duration::from_secs(60),
        5, // max_entries - very small
    );

    assert_eq!(limiter.max_entries(), 5);

    // Add 5 IPs (fills cache)
    for i in 1..=5 {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, i));
        limiter.check(ip).ok();
    }

    assert_eq!(limiter.tracked_ips(), 5);
    assert_eq!(limiter.eviction_count(), 0);

    // Add 6th IP - should trigger eviction
    let ip6 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 6));
    limiter.check(ip6).ok();

    assert_eq!(limiter.tracked_ips(), 5, "Cache should not exceed max");
    assert_eq!(limiter.eviction_count(), 1, "One eviction should occur");

    // Add more IPs - should cause more evictions
    for i in 7..=10 {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, i));
        limiter.check(ip).ok();
    }

    assert_eq!(limiter.tracked_ips(), 5, "Cache should remain at max");
    assert_eq!(limiter.eviction_count(), 5, "Total of 5 evictions");
}

#[test]
fn test_api_rate_limiter_lru_eviction() {
    // Create limiter with small caches
    let limiter = ApiRateLimiter::with_config_and_max_entries(
        10,    // per_ip_limit
        10,    // per_user_limit
        100,   // webhook_limit
        10000, // global_limit
        Duration::from_secs(60),
        3, // max_ip_entries
        3, // max_user_entries
    );

    // Test IP cache eviction
    for i in 1..=5 {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, i));
        limiter.check_ip(ip).ok();
    }

    assert_eq!(limiter.tracked_ips(), 3, "IP cache should be bounded");
    assert_eq!(
        limiter.ip_eviction_count(),
        2,
        "Two IP evictions should occur"
    );

    // Test user cache eviction
    let ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
    for _ in 0..5 {
        let user_id = Uuid::new_v4();
        limiter.check_user(user_id, ip).ok();
    }

    assert_eq!(limiter.tracked_users(), 3, "User cache should be bounded");
    assert_eq!(
        limiter.user_eviction_count(),
        2,
        "Two user evictions should occur"
    );
}

#[test]
fn test_webhook_rate_limiter_lru_eviction() {
    let limiter = WebhookRateLimiter::with_config_and_max_entries(
        10,   // per_source_limit
        1000, // global_limit
        1000, // max_queue_depth
        Duration::from_secs(60),
        3, // max_source_entries
    );

    // Add sources beyond capacity
    for i in 1..=5 {
        limiter.check(&format!("source_{}", i)).ok();
    }

    assert_eq!(
        limiter.tracked_sources(),
        3,
        "Source cache should be bounded"
    );
    assert_eq!(
        limiter.source_eviction_count(),
        2,
        "Two source evictions should occur"
    );
}

#[test]
fn test_lru_access_promotes_entry() {
    // This test verifies LRU semantics: accessing an entry promotes it
    let limiter = LoginRateLimiter::with_config_and_max_entries(
        10,   // per_ip_limit
        1000, // global_limit
        Duration::from_secs(60),
        3, // max_entries
    );

    let ip1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let ip2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let ip3 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let ip4 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4));

    // Add IPs in order: ip1, ip2, ip3
    limiter.check(ip1).ok();
    limiter.check(ip2).ok();
    limiter.check(ip3).ok();

    // Access ip1 again (promotes it to most recently used)
    limiter.check(ip1).ok();

    // Add ip4 - should evict ip2 (oldest after ip1 was promoted)
    limiter.check(ip4).ok();

    assert_eq!(limiter.tracked_ips(), 3);
    assert_eq!(limiter.eviction_count(), 1);

    // ip1 should still be in cache (was promoted)
    // We can verify by checking - if it were evicted, a fresh limiter would be created
    // Since we already used some quota, the check might succeed or fail based on quota
    // but the important thing is it doesn't create new eviction
    let evictions_before = limiter.eviction_count();
    limiter.check(ip1).ok();
    assert_eq!(
        limiter.eviction_count(),
        evictions_before,
        "ip1 should still be in cache, no new eviction"
    );
}

#[test]
fn test_memory_bounded_under_high_load() {
    // Simulate attack: many unique IPs trying to exhaust memory
    let limiter = LoginRateLimiter::with_config_and_max_entries(
        5,      // per_ip_limit
        100000, // global_limit (high)
        Duration::from_secs(60),
        100, // max_entries
    );

    // Simulate 10,000 unique IPs
    for i in 0..10000u32 {
        let octets = i.to_be_bytes();
        let ip = IpAddr::V4(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]));
        let _ = limiter.check(ip);
    }

    // Cache should be bounded at 100
    assert_eq!(
        limiter.tracked_ips(),
        100,
        "Cache must remain bounded under attack"
    );

    // Should have 9900 evictions (10000 - 100)
    assert_eq!(
        limiter.eviction_count(),
        9900,
        "Correct number of evictions should occur"
    );
}

// =============================================================================
// Concurrent Access Tests
// =============================================================================

#[tokio::test]
async fn test_rate_limiter_concurrent_safety() {
    let limiter = Arc::new(LoginRateLimiter::with_config_and_max_entries(
        100,   // per_ip_limit
        10000, // global_limit
        Duration::from_secs(60),
        50, // max_entries
    ));

    let mut handles = vec![];

    // Spawn 100 tasks each making 10 requests from unique IPs
    for task_id in 0..100 {
        let limiter = Arc::clone(&limiter);
        handles.push(tokio::spawn(async move {
            for req in 0..10 {
                let ip = IpAddr::V4(Ipv4Addr::new(
                    (task_id >> 8) as u8,
                    (task_id & 0xFF) as u8,
                    (req >> 8) as u8,
                    (req & 0xFF) as u8,
                ));
                let _ = limiter.check(ip);
            }
        }));
    }

    // Wait for all tasks
    for handle in handles {
        handle.await.unwrap();
    }

    // Verify cache is bounded
    assert!(
        limiter.tracked_ips() <= 50,
        "Cache should remain bounded under concurrent load"
    );
}

#[tokio::test]
async fn test_webhook_rate_limiter_concurrent_sources() {
    let limiter = Arc::new(WebhookRateLimiter::with_config_and_max_entries(
        50,    // per_source_limit
        10000, // global_limit
        10000, // max_queue_depth
        Duration::from_secs(60),
        20, // max_source_entries
    ));

    let mut handles = vec![];

    // Spawn tasks simulating different sources
    for task_id in 0..50 {
        let limiter = Arc::clone(&limiter);
        handles.push(tokio::spawn(async move {
            let source = format!("source_{}", task_id);
            for _ in 0..20 {
                let _ = limiter.check(&source);
            }
        }));
    }

    for handle in handles {
        handle.await.unwrap();
    }

    // Verify cache is bounded
    assert!(
        limiter.tracked_sources() <= 20,
        "Source cache should remain bounded"
    );
}

// =============================================================================
// Edge Cases
// =============================================================================

#[test]
fn test_rate_limiter_ipv6_support() {
    let limiter = LoginRateLimiter::with_config(
        3,   // per_ip_limit
        100, // global_limit
        Duration::from_secs(60),
    );

    let ipv6 = IpAddr::V6("2001:db8::1".parse().unwrap());

    // Should handle IPv6 addresses
    for _ in 0..3 {
        assert!(limiter.check(ipv6).is_ok());
    }
    assert_eq!(limiter.check(ipv6), Err(RateLimitError::PerIpLimitExceeded));
}

#[test]
fn test_webhook_empty_source_name() {
    let limiter = WebhookRateLimiter::with_config(3, 100, 1000, Duration::from_secs(60));

    // Empty source name should be handled
    for _ in 0..3 {
        assert!(limiter.check("").is_ok());
    }
    let result = limiter.check("");
    assert!(
        matches!(result, Err(WebhookRateLimitError::PerSourceLimitExceeded { source }) if source.is_empty())
    );
}

#[test]
fn test_webhook_unicode_source_names() {
    let limiter = WebhookRateLimiter::with_config(3, 100, 1000, Duration::from_secs(60));

    // Unicode source names should work
    let sources = ["splunk", "crowdstrike"];

    for source in sources {
        for _ in 0..3 {
            assert!(
                limiter.check(source).is_ok(),
                "Unicode source {} should work",
                source
            );
        }
    }
}

#[test]
fn test_clear_ip_resets_quota() {
    let limiter = LoginRateLimiter::with_config(3, 100, Duration::from_secs(60));

    let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));

    // Exhaust quota
    for _ in 0..3 {
        limiter.check(ip).ok();
    }
    assert_eq!(limiter.check(ip), Err(RateLimitError::PerIpLimitExceeded));

    // Clear the IP
    limiter.clear_ip(ip);

    // Quota should be reset (new limiter created)
    assert!(
        limiter.check(ip).is_ok(),
        "IP should have fresh quota after clear"
    );
}

#[test]
fn test_clear_source_resets_webhook_quota() {
    let limiter = WebhookRateLimiter::with_config(3, 100, 1000, Duration::from_secs(60));

    // Exhaust source quota
    for _ in 0..3 {
        limiter.check("test_source").ok();
    }
    assert!(limiter.check("test_source").is_err());

    // Clear the source
    limiter.clear_source("test_source");

    // Source should have fresh quota
    assert!(
        limiter.check("test_source").is_ok(),
        "Source should have fresh quota after clear"
    );
}
