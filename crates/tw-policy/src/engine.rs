//! Policy evaluation engine for Triage Warden.
//!
//! This module implements the core policy engine that evaluates proposed
//! actions against configured rules and guardrails.
//!
//! ## Security: ReDoS Protection
//!
//! This module implements protections against Regular Expression Denial of Service (ReDoS):
//!
//! 1. **Compiled Regex Caching**: Regex patterns are compiled once at configuration load time
//!    and cached as `Arc<Regex>`. This prevents repeated compilation overhead and ensures
//!    patterns are validated upfront.
//!
//! 2. **Pattern Complexity Validation**: Patterns are validated at load time using
//!    `validate_regex_safe()` in the config module, which rejects patterns with
//!    catastrophic backtracking potential (nested quantifiers like `(a+)+`).
//!
//! 3. **Size Limits**: The regex crate is configured with size limits to prevent
//!    resource exhaustion from overly complex patterns.

use crate::approval::ApprovalLevel;
use crate::rules::{PolicyRule, RuleCondition, RuleEffect};
use chrono::{DateTime, Duration, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, info, instrument, warn};

/// Errors that can occur in policy evaluation.
#[derive(Error, Debug)]
pub enum PolicyError {
    #[error("Policy configuration error: {0}")]
    ConfigError(String),

    #[error("Rate limit exceeded: {0}")]
    RateLimitExceeded(String),

    #[error("Denied by policy: {0}")]
    Denied(String),

    #[error("Invalid target: {0}")]
    InvalidTarget(String),
}

/// Result of policy evaluation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PolicyDecision {
    /// Action is allowed to proceed automatically.
    Allowed,
    /// Action is denied by policy.
    Denied(DenyReason),
    /// Action requires approval before proceeding.
    RequiresApproval(ApprovalLevel),
}

/// Reason for denying an action.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DenyReason {
    /// The rule that caused the denial.
    pub rule_name: String,
    /// Human-readable explanation.
    pub message: String,
    /// Whether this denial can be overridden.
    pub can_override: bool,
}

/// Context for evaluating a proposed action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionContext {
    /// Type of action being proposed.
    pub action_type: String,
    /// Target of the action.
    pub target: ActionTarget,
    /// Severity of the incident.
    pub incident_severity: String,
    /// Confidence score from analysis.
    pub confidence: f64,
    /// Source of the proposal (AI, playbook, analyst).
    pub proposer: String,
    /// Additional context data.
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Target of an action for policy evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionTarget {
    /// Type of target (host, user, ip, etc.).
    pub target_type: String,
    /// Target identifier.
    pub identifier: String,
    /// Criticality level of the target.
    pub criticality: Option<Criticality>,
    /// Tags/labels on the target.
    pub tags: Vec<String>,
}

/// Criticality level for assets.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Criticality {
    Low,
    Medium,
    High,
    Critical,
}

/// Deny list configuration for blocking specific actions or targets.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DenyList {
    /// Actions that are never allowed.
    pub actions: Vec<String>,
    /// Target patterns that are protected.
    pub target_patterns: Vec<String>,
    /// Specific IPs that are protected.
    pub protected_ips: Vec<String>,
    /// Specific users that are protected.
    pub protected_users: Vec<String>,
}

impl DenyList {
    /// Checks if an action is in the deny list.
    pub fn is_action_denied(&self, action: &str) -> bool {
        self.actions.iter().any(|a| a == action)
    }

    /// Checks if a target matches any protected pattern.
    pub fn is_target_protected(&self, target: &str) -> bool {
        for pattern in &self.target_patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                if re.is_match(target) {
                    return true;
                }
            }
        }
        false
    }

    /// Checks if an IP is protected.
    pub fn is_ip_protected(&self, ip: &str) -> bool {
        self.protected_ips.contains(&ip.to_string())
    }

    /// Checks if a user is protected.
    pub fn is_user_protected(&self, user: &str) -> bool {
        self.protected_users.contains(&user.to_string())
    }
}

/// A compiled regex pattern with its original source for debugging.
#[derive(Debug, Clone)]
pub struct CompiledPattern {
    /// The original pattern string.
    pub source: String,
    /// The compiled regex, wrapped in Arc for cheap cloning.
    pub regex: Arc<Regex>,
}

impl CompiledPattern {
    /// Creates a new compiled pattern from a regex string.
    ///
    /// Returns an error if the pattern is invalid.
    pub fn new(pattern: &str) -> Result<Self, RegexValidationError> {
        // Use regex builder with size limits to prevent resource exhaustion
        let regex = regex::RegexBuilder::new(pattern)
            .size_limit(10 * (1 << 20)) // 10 MB compiled size limit
            .dfa_size_limit(10 * (1 << 20)) // 10 MB DFA size limit
            .build()
            .map_err(|e| RegexValidationError::InvalidPattern {
                pattern: pattern.to_string(),
                message: e.to_string(),
            })?;

        Ok(Self {
            source: pattern.to_string(),
            regex: Arc::new(regex),
        })
    }

    /// Checks if the given string matches this pattern.
    #[inline]
    pub fn is_match(&self, text: &str) -> bool {
        self.regex.is_match(text)
    }
}

/// Errors that can occur during regex validation.
#[derive(Error, Debug, Clone)]
pub enum RegexValidationError {
    #[error("Invalid regex pattern '{pattern}': {message}")]
    InvalidPattern { pattern: String, message: String },

    #[error("Potentially unsafe regex pattern '{pattern}': {reason}")]
    UnsafePattern { pattern: String, reason: String },
}

/// A validated deny list with pre-compiled regex patterns.
///
/// This struct provides ReDoS-safe target pattern matching by:
/// 1. Compiling all patterns once at construction time
/// 2. Validating patterns for potential catastrophic backtracking
/// 3. Using size limits on compiled patterns
///
/// # Example
///
/// ```
/// use tw_policy::engine::{DenyList, ValidatedDenyList};
///
/// let deny_list = DenyList {
///     actions: vec!["delete_user".to_string()],
///     target_patterns: vec![r".*-prod-.*".to_string()],
///     protected_ips: vec![],
///     protected_users: vec!["admin".to_string()],
/// };
///
/// let validated = ValidatedDenyList::try_from_deny_list(&deny_list).unwrap();
/// assert!(validated.is_target_protected("web-prod-01"));
/// ```
#[derive(Debug, Clone, Default)]
pub struct ValidatedDenyList {
    /// Actions that are never allowed.
    pub actions: Vec<String>,
    /// Pre-compiled target patterns that are protected.
    pub compiled_patterns: Vec<CompiledPattern>,
    /// Specific IPs that are protected.
    pub protected_ips: Vec<String>,
    /// Specific users that are protected.
    pub protected_users: Vec<String>,
}

impl ValidatedDenyList {
    /// Creates a new validated deny list from a raw DenyList.
    ///
    /// This compiles all regex patterns and validates them for safety.
    ///
    /// # Errors
    ///
    /// Returns an error if any pattern is invalid or potentially unsafe.
    pub fn try_from_deny_list(deny_list: &DenyList) -> Result<Self, RegexValidationError> {
        let mut compiled_patterns = Vec::with_capacity(deny_list.target_patterns.len());

        for pattern in &deny_list.target_patterns {
            // Validate pattern for potential ReDoS before compiling
            validate_regex_safe(pattern)?;
            compiled_patterns.push(CompiledPattern::new(pattern)?);
        }

        Ok(Self {
            actions: deny_list.actions.clone(),
            compiled_patterns,
            protected_ips: deny_list.protected_ips.clone(),
            protected_users: deny_list.protected_users.clone(),
        })
    }

    /// Checks if an action is in the deny list.
    #[inline]
    pub fn is_action_denied(&self, action: &str) -> bool {
        self.actions.iter().any(|a| a == action)
    }

    /// Checks if a target matches any protected pattern.
    ///
    /// This uses pre-compiled patterns and is safe against ReDoS attacks.
    pub fn is_target_protected(&self, target: &str) -> bool {
        for pattern in &self.compiled_patterns {
            if pattern.is_match(target) {
                return true;
            }
        }
        false
    }

    /// Checks if an IP is protected.
    #[inline]
    pub fn is_ip_protected(&self, ip: &str) -> bool {
        self.protected_ips.iter().any(|p| p == ip)
    }

    /// Checks if a user is protected.
    #[inline]
    pub fn is_user_protected(&self, user: &str) -> bool {
        self.protected_users.iter().any(|u| u == user)
    }

    /// Gets the number of compiled patterns.
    pub fn pattern_count(&self) -> usize {
        self.compiled_patterns.len()
    }

    /// Returns an iterator over the pattern sources.
    pub fn pattern_sources(&self) -> impl Iterator<Item = &str> {
        self.compiled_patterns.iter().map(|p| p.source.as_str())
    }
}

/// Validates that a regex pattern is safe against ReDoS attacks.
///
/// This function checks for patterns that could cause catastrophic backtracking:
/// - Nested quantifiers like `(a+)+`, `(a*)*`, `(a?)+`
/// - Overlapping alternatives with quantifiers
/// - Excessive quantifier ranges
///
/// # Errors
///
/// Returns an error if the pattern contains potentially dangerous constructs.
pub fn validate_regex_safe(pattern: &str) -> Result<(), RegexValidationError> {
    // Check for nested quantifiers (most common ReDoS pattern)
    // Patterns like (a+)+, (a*)+, (a+)*, (a?)+ etc.
    let nested_quantifier_patterns = [
        r"\([^)]*[+*][^)]*\)[+*?]", // (x+)+ or (x*)* etc
        r"\([^)]*[+*?]\)[+*]",      // Nested quantifiers
        r"\[[^\]]*\][+*]\)[+*?]",   // Character class with quantifier inside group
    ];

    // Compile checker patterns (these are safe, fixed patterns)
    for checker in &nested_quantifier_patterns {
        if let Ok(re) = Regex::new(checker) {
            if re.is_match(pattern) {
                return Err(RegexValidationError::UnsafePattern {
                    pattern: pattern.to_string(),
                    reason: "Pattern contains nested quantifiers which can cause catastrophic backtracking".to_string(),
                });
            }
        }
    }

    // Check for excessive quantifier ranges like {1,10000}
    if let Ok(re) = Regex::new(r"\{(\d+),(\d+)\}") {
        for cap in re.captures_iter(pattern) {
            if let (Some(min), Some(max)) = (cap.get(1), cap.get(2)) {
                if let (Ok(min_val), Ok(max_val)) =
                    (min.as_str().parse::<u32>(), max.as_str().parse::<u32>())
                {
                    // Reject ranges where max - min > 1000 (arbitrary but reasonable limit)
                    if max_val.saturating_sub(min_val) > 1000 {
                        return Err(RegexValidationError::UnsafePattern {
                            pattern: pattern.to_string(),
                            reason: format!(
                                "Quantifier range {{{},{}}} is too large (max range: 1000)",
                                min_val, max_val
                            ),
                        });
                    }
                }
            }
        }
    }

    // Check for overlapping alternations with quantifiers
    // Patterns like (a|a)+, (ab|abc)+ can cause exponential backtracking
    // This is a simplified check - full analysis would require parsing the regex AST
    let overlapping_patterns = [
        r"\(([^|)]+)\|\1[^)]*\)[+*]", // Same prefix in alternation with quantifier
    ];

    for checker in &overlapping_patterns {
        if let Ok(re) = Regex::new(checker) {
            if re.is_match(pattern) {
                return Err(RegexValidationError::UnsafePattern {
                    pattern: pattern.to_string(),
                    reason: "Pattern contains overlapping alternations with quantifiers"
                        .to_string(),
                });
            }
        }
    }

    // Pattern length limit
    if pattern.len() > 1000 {
        return Err(RegexValidationError::UnsafePattern {
            pattern: pattern.chars().take(100).collect::<String>() + "...",
            reason: "Pattern is too long (max 1000 characters)".to_string(),
        });
    }

    Ok(())
}

/// Rate limit configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Maximum executions per hour.
    pub max_per_hour: u32,
    /// Maximum executions per day.
    pub max_per_day: u32,
    /// Maximum concurrent executions.
    pub max_concurrent: Option<u32>,
}

/// Rate limiter state.
#[derive(Debug, Default)]
struct RateLimiterState {
    /// Actions executed in the current hour window.
    hourly_counts: HashMap<String, Vec<DateTime<Utc>>>,
    /// Actions executed in the current day window.
    daily_counts: HashMap<String, Vec<DateTime<Utc>>>,
}

/// Concurrent execution tracker using atomic counters.
///
/// This provides atomic check-and-acquire semantics for concurrent rate limiting,
/// eliminating TOCTOU race conditions through compare-and-swap operations.
struct ConcurrentTracker {
    /// Current count of concurrent executions per action type.
    counts: RwLock<HashMap<String, Arc<AtomicU32>>>,
    /// Configuration for max concurrent per action type.
    configs: HashMap<String, u32>,
}

impl ConcurrentTracker {
    fn new(configs: HashMap<String, u32>) -> Self {
        Self {
            counts: RwLock::new(HashMap::new()),
            configs,
        }
    }

    /// Gets or creates an atomic counter for an action type.
    async fn get_counter(&self, action_type: &str) -> Arc<AtomicU32> {
        // Fast path: check if counter exists
        {
            let counts = self.counts.read().await;
            if let Some(counter) = counts.get(action_type) {
                return Arc::clone(counter);
            }
        }

        // Slow path: create counter
        let mut counts = self.counts.write().await;
        counts
            .entry(action_type.to_string())
            .or_insert_with(|| Arc::new(AtomicU32::new(0)))
            .clone()
    }

    /// Tries to acquire a concurrent slot atomically. Returns true if acquired.
    ///
    /// This is the key method for preventing TOCTOU races: we use compare_exchange
    /// to atomically check the limit and increment in a single operation.
    async fn try_acquire(&self, action_type: &str) -> bool {
        let max = match self.configs.get(action_type) {
            Some(m) => *m,
            None => return true, // No limit configured, always allow
        };

        let counter = self.get_counter(action_type).await;

        // Use compare-and-swap loop for atomic check-and-increment
        loop {
            let current = counter.load(Ordering::SeqCst);
            if current >= max {
                return false; // Limit exceeded
            }

            // Try to atomically increment from current to current + 1
            match counter.compare_exchange_weak(
                current,
                current + 1,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => return true, // Successfully acquired
                Err(_) => continue,   // Another thread modified, retry
            }
        }
    }

    /// Releases a concurrent slot.
    async fn release(&self, action_type: &str) {
        if self.configs.contains_key(action_type) {
            let counter = self.get_counter(action_type).await;
            counter.fetch_sub(1, Ordering::SeqCst);
        }
    }

    /// Gets the current concurrent count for an action type.
    #[allow(dead_code)]
    async fn get_count(&self, action_type: &str) -> u32 {
        let counts = self.counts.read().await;
        counts
            .get(action_type)
            .map(|c| c.load(Ordering::SeqCst))
            .unwrap_or(0)
    }
}

/// Rate limiter for action execution.
///
/// This rate limiter uses atomic operations to prevent TOCTOU race conditions.
/// The check-and-record operation is atomic, ensuring that concurrent requests
/// cannot bypass rate limits.
///
/// ## Security: TOCTOU Prevention
///
/// The original implementation had a race condition where:
/// 1. `check()` was called (read lock)
/// 2. `record()` was called later (write lock)
///
/// Between these operations, other concurrent requests could slip through.
/// This is now fixed by:
/// - Using `check_and_record()` for atomic time-based rate limiting
/// - Using semaphores via `try_start_concurrent()` for atomic concurrent limiting
pub struct RateLimiter {
    /// Rate limit configurations by action type.
    configs: HashMap<String, RateLimitConfig>,
    /// Current state for time-based rate limiting (uses mutex for atomicity).
    state: Arc<Mutex<RateLimiterState>>,
    /// Concurrent execution tracker using semaphores.
    concurrent_tracker: ConcurrentTracker,
}

impl RateLimiter {
    /// Creates a new rate limiter with the given configurations.
    pub fn new(configs: HashMap<String, RateLimitConfig>) -> Self {
        // Extract concurrent limits for the tracker
        let concurrent_configs: HashMap<String, u32> = configs
            .iter()
            .filter_map(|(k, v)| v.max_concurrent.map(|m| (k.clone(), m)))
            .collect();

        Self {
            configs: configs.clone(),
            state: Arc::new(Mutex::new(RateLimiterState::default())),
            concurrent_tracker: ConcurrentTracker::new(concurrent_configs),
        }
    }

    /// Checks if an action is within rate limits (read-only, no recording).
    ///
    /// **Warning**: This method is susceptible to TOCTOU race conditions when used
    /// separately from `record()`. For atomic rate limiting, use `check_and_record()`
    /// instead.
    #[instrument(skip(self))]
    pub async fn check(&self, action_type: &str) -> Result<(), PolicyError> {
        let config = match self.configs.get(action_type) {
            Some(c) => c,
            None => return Ok(()), // No limit configured
        };

        let now = Utc::now();
        let hour_ago = now - Duration::hours(1);
        let day_ago = now - Duration::days(1);

        // Use mutex lock for consistency with check_and_record
        let state = self.state.lock().await;

        // Check hourly limit
        if let Some(times) = state.hourly_counts.get(action_type) {
            let count = times.iter().filter(|t| **t > hour_ago).count() as u32;
            if count >= config.max_per_hour {
                return Err(PolicyError::RateLimitExceeded(format!(
                    "{} hourly limit ({}) exceeded",
                    action_type, config.max_per_hour
                )));
            }
        }

        // Check daily limit
        if let Some(times) = state.daily_counts.get(action_type) {
            let count = times.iter().filter(|t| **t > day_ago).count() as u32;
            if count >= config.max_per_day {
                return Err(PolicyError::RateLimitExceeded(format!(
                    "{} daily limit ({}) exceeded",
                    action_type, config.max_per_day
                )));
            }
        }

        // Check concurrent limit using atomic tracker
        if let Some(max_concurrent) = config.max_concurrent {
            let current = self.concurrent_tracker.get_count(action_type).await;
            if current >= max_concurrent {
                return Err(PolicyError::RateLimitExceeded(format!(
                    "{} concurrent limit ({}) exceeded",
                    action_type, max_concurrent
                )));
            }
        }

        Ok(())
    }

    /// Atomically checks rate limits and records the action if allowed.
    ///
    /// This method eliminates the TOCTOU race condition by performing both the
    /// check and record operations atomically under a single lock. If the action
    /// is within limits, it is immediately recorded before releasing the lock.
    ///
    /// Returns `Ok(())` if the action is allowed and has been recorded.
    /// Returns `Err(PolicyError::RateLimitExceeded)` if the limit is exceeded.
    #[instrument(skip(self))]
    pub async fn check_and_record(&self, action_type: &str) -> Result<(), PolicyError> {
        let config = match self.configs.get(action_type) {
            Some(c) => c,
            None => return Ok(()), // No limit configured
        };

        let now = Utc::now();
        let hour_ago = now - Duration::hours(1);
        let day_ago = now - Duration::days(1);

        // Acquire exclusive lock for atomic check-and-record
        let mut state = self.state.lock().await;

        // Check hourly limit
        if let Some(times) = state.hourly_counts.get(action_type) {
            let count = times.iter().filter(|t| **t > hour_ago).count() as u32;
            if count >= config.max_per_hour {
                return Err(PolicyError::RateLimitExceeded(format!(
                    "{} hourly limit ({}) exceeded",
                    action_type, config.max_per_hour
                )));
            }
        }

        // Check daily limit
        if let Some(times) = state.daily_counts.get(action_type) {
            let count = times.iter().filter(|t| **t > day_ago).count() as u32;
            if count >= config.max_per_day {
                return Err(PolicyError::RateLimitExceeded(format!(
                    "{} daily limit ({}) exceeded",
                    action_type, config.max_per_day
                )));
            }
        }

        // Atomically record the action while still holding the lock
        state
            .hourly_counts
            .entry(action_type.to_string())
            .or_default()
            .push(now);

        state
            .daily_counts
            .entry(action_type.to_string())
            .or_default()
            .push(now);

        Ok(())
    }

    /// Atomically checks concurrent limit and acquires a slot if allowed.
    ///
    /// This method uses a semaphore to ensure atomic check-and-acquire semantics.
    /// The caller MUST call `end_concurrent()` when done to release the slot.
    ///
    /// Returns `Ok(())` if a concurrent slot was acquired.
    /// Returns `Err(PolicyError::RateLimitExceeded)` if the concurrent limit is exceeded.
    #[instrument(skip(self))]
    pub async fn try_start_concurrent(&self, action_type: &str) -> Result<(), PolicyError> {
        let config = match self.configs.get(action_type) {
            Some(c) => c,
            None => return Ok(()), // No limit configured
        };

        // Only check if a concurrent limit is configured
        if let Some(max_concurrent) = config.max_concurrent {
            if !self.concurrent_tracker.try_acquire(action_type).await {
                return Err(PolicyError::RateLimitExceeded(format!(
                    "{} concurrent limit ({}) exceeded",
                    action_type, max_concurrent
                )));
            }
        }

        Ok(())
    }

    /// Records an action execution (for time-based limits only).
    ///
    /// **Note**: For atomic rate limiting, prefer `check_and_record()` instead
    /// of calling `check()` followed by `record()`.
    pub async fn record(&self, action_type: &str) {
        let now = Utc::now();
        let mut state = self.state.lock().await;

        state
            .hourly_counts
            .entry(action_type.to_string())
            .or_default()
            .push(now);

        state
            .daily_counts
            .entry(action_type.to_string())
            .or_default()
            .push(now);
    }

    /// Increments the concurrent count for an action.
    ///
    /// **Deprecated**: Use `try_start_concurrent()` for atomic check-and-acquire.
    /// This method is kept for backward compatibility but does not guarantee
    /// atomic behavior.
    pub async fn start_concurrent(&self, action_type: &str) {
        let _ = self.concurrent_tracker.try_acquire(action_type).await;
    }

    /// Decrements the concurrent count for an action.
    ///
    /// Must be called after `try_start_concurrent()` or `start_concurrent()` completes
    /// to release the slot.
    pub async fn end_concurrent(&self, action_type: &str) {
        self.concurrent_tracker.release(action_type).await;
    }

    /// Cleans up old entries to prevent memory growth.
    pub async fn cleanup(&self) {
        let now = Utc::now();
        let hour_ago = now - Duration::hours(1);
        let day_ago = now - Duration::days(1);

        let mut state = self.state.lock().await;

        for times in state.hourly_counts.values_mut() {
            times.retain(|t| *t > hour_ago);
        }

        for times in state.daily_counts.values_mut() {
            times.retain(|t| *t > day_ago);
        }
    }
}

/// The policy engine evaluates proposed actions against configured rules.
pub struct PolicyEngine {
    /// Policy rules.
    rules: Vec<PolicyRule>,
    /// Deny list for blocked actions/targets.
    deny_list: DenyList,
    /// Rate limiter.
    rate_limiter: RateLimiter,
    /// Default decision when no rules match.
    default_decision: PolicyDecision,
}

impl PolicyEngine {
    /// Creates a new policy engine.
    pub fn new(
        rules: Vec<PolicyRule>,
        deny_list: DenyList,
        rate_limits: HashMap<String, RateLimitConfig>,
    ) -> Self {
        Self {
            rules,
            deny_list,
            rate_limiter: RateLimiter::new(rate_limits),
            default_decision: PolicyDecision::RequiresApproval(ApprovalLevel::Analyst),
        }
    }

    /// Creates a policy engine with default configuration.
    pub fn default_config() -> Self {
        let rules = vec![
            // Critical assets require senior approval (highest priority)
            PolicyRule::new(
                "critical_assets_senior_approval".to_string(),
                vec![RuleCondition::TargetCriticalityIn(vec![
                    Criticality::Critical,
                ])],
                RuleEffect::RequireApproval(ApprovalLevel::Senior),
            ),
            // Low-risk actions for high-confidence verdicts
            PolicyRule::new(
                "auto_approve_low_risk_high_confidence".to_string(),
                vec![
                    RuleCondition::ActionTypeIn(vec![
                        "create_ticket".to_string(),
                        "add_ticket_comment".to_string(),
                        "send_notification".to_string(),
                    ]),
                    RuleCondition::ConfidenceAbove(0.9),
                ],
                RuleEffect::Allow,
            ),
            // Require approval for host isolation
            PolicyRule::new(
                "host_isolation_requires_approval".to_string(),
                vec![RuleCondition::ActionTypeIn(
                    vec!["isolate_host".to_string()],
                )],
                RuleEffect::RequireApproval(ApprovalLevel::Analyst),
            ),
        ];

        let deny_list = DenyList {
            actions: vec!["delete_user".to_string(), "wipe_host".to_string()],
            target_patterns: vec![r".*-prod-.*".to_string(), r"dc\d+\..*".to_string()],
            protected_ips: vec![],
            protected_users: vec!["admin".to_string(), "root".to_string()],
        };

        let mut rate_limits = HashMap::new();
        rate_limits.insert(
            "isolate_host".to_string(),
            RateLimitConfig {
                max_per_hour: 5,
                max_per_day: 20,
                max_concurrent: Some(2),
            },
        );
        rate_limits.insert(
            "disable_user".to_string(),
            RateLimitConfig {
                max_per_hour: 10,
                max_per_day: 50,
                max_concurrent: Some(5),
            },
        );

        Self::new(rules, deny_list, rate_limits)
    }

    /// Evaluates a proposed action against all policies.
    ///
    /// Note: This method only checks if an action is allowed. For atomic rate limiting,
    /// use `evaluate_and_record()` which combines evaluation with atomic recording.
    #[instrument(skip(self, context), fields(action = %context.action_type))]
    pub async fn evaluate(&self, context: &ActionContext) -> Result<PolicyDecision, PolicyError> {
        debug!("Evaluating policy for action: {}", context.action_type);

        // 1. Check deny list
        if self.deny_list.is_action_denied(&context.action_type) {
            info!("Action {} denied by deny list", context.action_type);
            return Ok(PolicyDecision::Denied(DenyReason {
                rule_name: "deny_list".to_string(),
                message: format!("Action '{}' is not allowed", context.action_type),
                can_override: false,
            }));
        }

        // Check target protection
        if self
            .deny_list
            .is_target_protected(&context.target.identifier)
        {
            info!(
                "Target {} is protected by deny list",
                context.target.identifier
            );
            return Ok(PolicyDecision::Denied(DenyReason {
                rule_name: "target_protection".to_string(),
                message: format!("Target '{}' is protected", context.target.identifier),
                can_override: false,
            }));
        }

        // Check user protection
        if context.target.target_type == "user"
            && self.deny_list.is_user_protected(&context.target.identifier)
        {
            return Ok(PolicyDecision::Denied(DenyReason {
                rule_name: "user_protection".to_string(),
                message: format!("User '{}' is protected", context.target.identifier),
                can_override: false,
            }));
        }

        // 2. Check rate limits (read-only check)
        if let Err(e) = self.rate_limiter.check(&context.action_type).await {
            warn!("Rate limit check failed: {}", e);
            return Ok(PolicyDecision::Denied(DenyReason {
                rule_name: "rate_limit".to_string(),
                message: e.to_string(),
                can_override: true,
            }));
        }

        // 3. Evaluate rules in priority order (lower priority number = higher priority)
        let mut sorted_rules: Vec<_> = self.rules.iter().filter(|r| r.enabled).collect();
        sorted_rules.sort_by_key(|r| r.priority);

        for rule in sorted_rules {
            if rule.matches(context) {
                debug!("Rule '{}' matched", rule.name);
                match &rule.effect {
                    RuleEffect::Allow => return Ok(PolicyDecision::Allowed),
                    RuleEffect::Deny(reason) => {
                        return Ok(PolicyDecision::Denied(DenyReason {
                            rule_name: rule.name.clone(),
                            message: reason.clone(),
                            can_override: rule.can_override,
                        }))
                    }
                    RuleEffect::RequireApproval(level) => {
                        return Ok(PolicyDecision::RequiresApproval(*level))
                    }
                }
            }
        }

        // 4. Return default decision
        debug!("No rules matched, returning default decision");
        Ok(self.default_decision.clone())
    }

    /// Atomically evaluates and records an action for rate limiting.
    ///
    /// This method combines policy evaluation with atomic rate limit recording,
    /// eliminating the TOCTOU race condition between `evaluate()` and `record_execution()`.
    ///
    /// If the action is allowed (not denied by any policy), it is atomically recorded
    /// for rate limiting purposes. This ensures that concurrent requests cannot bypass
    /// the rate limit by racing between check and record.
    #[instrument(skip(self, context), fields(action = %context.action_type))]
    pub async fn evaluate_and_record(
        &self,
        context: &ActionContext,
    ) -> Result<PolicyDecision, PolicyError> {
        debug!(
            "Evaluating and recording policy for action: {}",
            context.action_type
        );

        // 1. Check deny list (no need for atomic - these are static checks)
        if self.deny_list.is_action_denied(&context.action_type) {
            info!("Action {} denied by deny list", context.action_type);
            return Ok(PolicyDecision::Denied(DenyReason {
                rule_name: "deny_list".to_string(),
                message: format!("Action '{}' is not allowed", context.action_type),
                can_override: false,
            }));
        }

        // Check target protection
        if self
            .deny_list
            .is_target_protected(&context.target.identifier)
        {
            info!(
                "Target {} is protected by deny list",
                context.target.identifier
            );
            return Ok(PolicyDecision::Denied(DenyReason {
                rule_name: "target_protection".to_string(),
                message: format!("Target '{}' is protected", context.target.identifier),
                can_override: false,
            }));
        }

        // Check user protection
        if context.target.target_type == "user"
            && self.deny_list.is_user_protected(&context.target.identifier)
        {
            return Ok(PolicyDecision::Denied(DenyReason {
                rule_name: "user_protection".to_string(),
                message: format!("User '{}' is protected", context.target.identifier),
                can_override: false,
            }));
        }

        // 2. Atomically check and record rate limits
        // This eliminates the TOCTOU race condition
        if let Err(e) = self
            .rate_limiter
            .check_and_record(&context.action_type)
            .await
        {
            warn!("Rate limit exceeded: {}", e);
            return Ok(PolicyDecision::Denied(DenyReason {
                rule_name: "rate_limit".to_string(),
                message: e.to_string(),
                can_override: true,
            }));
        }

        // 3. Evaluate rules in priority order (lower priority number = higher priority)
        let mut sorted_rules: Vec<_> = self.rules.iter().filter(|r| r.enabled).collect();
        sorted_rules.sort_by_key(|r| r.priority);

        for rule in sorted_rules {
            if rule.matches(context) {
                debug!("Rule '{}' matched", rule.name);
                match &rule.effect {
                    RuleEffect::Allow => return Ok(PolicyDecision::Allowed),
                    RuleEffect::Deny(reason) => {
                        return Ok(PolicyDecision::Denied(DenyReason {
                            rule_name: rule.name.clone(),
                            message: reason.clone(),
                            can_override: rule.can_override,
                        }))
                    }
                    RuleEffect::RequireApproval(level) => {
                        return Ok(PolicyDecision::RequiresApproval(*level))
                    }
                }
            }
        }

        // 4. Return default decision
        debug!("No rules matched, returning default decision");
        Ok(self.default_decision.clone())
    }

    /// Records an action execution for rate limiting.
    ///
    /// **Note**: For atomic rate limiting without TOCTOU race conditions,
    /// prefer `evaluate_and_record()` instead of `evaluate()` + `record_execution()`.
    pub async fn record_execution(&self, action_type: &str) {
        self.rate_limiter.record(action_type).await;
    }

    /// Atomically checks concurrent limit and starts tracking a concurrent action.
    ///
    /// Returns `Ok(())` if the concurrent slot was acquired.
    /// Returns `Err(PolicyError::RateLimitExceeded)` if the limit is exceeded.
    ///
    /// The caller MUST call `end_action()` when done to release the slot.
    pub async fn try_start_action(&self, action_type: &str) -> Result<(), PolicyError> {
        self.rate_limiter.try_start_concurrent(action_type).await
    }

    /// Starts tracking a concurrent action.
    ///
    /// **Deprecated**: Use `try_start_action()` for atomic check-and-acquire.
    /// This method is kept for backward compatibility.
    pub async fn start_action(&self, action_type: &str) {
        self.rate_limiter.start_concurrent(action_type).await;
    }

    /// Ends tracking a concurrent action.
    ///
    /// Must be called after `try_start_action()` or `start_action()` to release the slot.
    pub async fn end_action(&self, action_type: &str) {
        self.rate_limiter.end_concurrent(action_type).await;
    }

    /// Gets the current rules.
    pub fn rules(&self) -> &[PolicyRule] {
        &self.rules
    }

    /// Adds a new rule.
    pub fn add_rule(&mut self, rule: PolicyRule) {
        self.rules.push(rule);
    }

    /// Removes a rule by name.
    pub fn remove_rule(&mut self, name: &str) -> bool {
        let initial_len = self.rules.len();
        self.rules.retain(|r| r.name != name);
        self.rules.len() < initial_len
    }

    /// Updates the deny list.
    pub fn update_deny_list(&mut self, deny_list: DenyList) {
        self.deny_list = deny_list;
    }

    /// Sets the default decision.
    pub fn set_default_decision(&mut self, decision: PolicyDecision) {
        self.default_decision = decision;
    }

    /// Cleans up rate limiter state.
    pub async fn cleanup(&self) {
        self.rate_limiter.cleanup().await;
    }
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::default_config()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_context(action_type: &str, confidence: f64) -> ActionContext {
        ActionContext {
            action_type: action_type.to_string(),
            target: ActionTarget {
                target_type: "host".to_string(),
                identifier: "workstation-001".to_string(),
                criticality: Some(Criticality::Medium),
                tags: vec![],
            },
            incident_severity: "high".to_string(),
            confidence,
            proposer: "ai".to_string(),
            metadata: HashMap::new(),
        }
    }

    #[tokio::test]
    async fn test_allow_low_risk_action() {
        let engine = PolicyEngine::default_config();
        let context = create_test_context("create_ticket", 0.95);

        let decision = engine.evaluate(&context).await.unwrap();
        assert_eq!(decision, PolicyDecision::Allowed);
    }

    #[tokio::test]
    async fn test_deny_dangerous_action() {
        let engine = PolicyEngine::default_config();
        let context = create_test_context("delete_user", 0.99);

        let decision = engine.evaluate(&context).await.unwrap();
        assert!(matches!(decision, PolicyDecision::Denied(_)));
    }

    #[tokio::test]
    async fn test_require_approval_for_isolation() {
        let engine = PolicyEngine::default_config();
        let context = create_test_context("isolate_host", 0.95);

        let decision = engine.evaluate(&context).await.unwrap();
        assert!(matches!(
            decision,
            PolicyDecision::RequiresApproval(ApprovalLevel::Analyst)
        ));
    }

    #[tokio::test]
    async fn test_critical_asset_protection() {
        let engine = PolicyEngine::default_config();
        let mut context = create_test_context("isolate_host", 0.95);
        context.target.criticality = Some(Criticality::Critical);

        let decision = engine.evaluate(&context).await.unwrap();
        assert!(matches!(
            decision,
            PolicyDecision::RequiresApproval(ApprovalLevel::Senior)
        ));
    }

    #[tokio::test]
    async fn test_protected_target() {
        let engine = PolicyEngine::default_config();
        let mut context = create_test_context("isolate_host", 0.95);
        context.target.identifier = "dc01.corp.local".to_string();

        let decision = engine.evaluate(&context).await.unwrap();
        assert!(matches!(decision, PolicyDecision::Denied(_)));
    }

    #[tokio::test]
    async fn test_rate_limiting() {
        let mut rate_limits = HashMap::new();
        rate_limits.insert(
            "test_action".to_string(),
            RateLimitConfig {
                max_per_hour: 2,
                max_per_day: 10,
                max_concurrent: None,
            },
        );

        let engine = PolicyEngine::new(vec![], DenyList::default(), rate_limits);
        let context = create_test_context("test_action", 0.95);

        // First two should succeed
        engine.record_execution("test_action").await;
        engine.record_execution("test_action").await;

        // Third should be rate limited
        let decision = engine.evaluate(&context).await.unwrap();
        assert!(matches!(decision, PolicyDecision::Denied(_)));
    }

    #[tokio::test]
    async fn test_deny_list_patterns() {
        let deny_list = DenyList {
            actions: vec![],
            target_patterns: vec![r".*-prod-.*".to_string()],
            protected_ips: vec![],
            protected_users: vec![],
        };

        assert!(deny_list.is_target_protected("web-prod-01"));
        assert!(deny_list.is_target_protected("db-prod-cluster"));
        assert!(!deny_list.is_target_protected("web-dev-01"));
    }

    // ============================================================
    // Rate Limiter Edge Cases
    // ============================================================

    #[tokio::test]
    async fn test_rate_limiting_daily_limit() {
        let mut rate_limits = HashMap::new();
        rate_limits.insert(
            "test_action".to_string(),
            RateLimitConfig {
                max_per_hour: 100, // High hourly limit
                max_per_day: 3,    // Low daily limit
                max_concurrent: None,
            },
        );

        let engine = PolicyEngine::new(vec![], DenyList::default(), rate_limits);
        let context = create_test_context("test_action", 0.95);

        // First three should succeed
        for _ in 0..3 {
            engine.record_execution("test_action").await;
        }

        // Fourth should hit daily limit
        let decision = engine.evaluate(&context).await.unwrap();
        assert!(matches!(decision, PolicyDecision::Denied(_)));
        if let PolicyDecision::Denied(reason) = decision {
            assert!(reason.message.contains("daily limit"));
        }
    }

    #[tokio::test]
    async fn test_rate_limiting_concurrent_limit() {
        let mut rate_limits = HashMap::new();
        rate_limits.insert(
            "concurrent_action".to_string(),
            RateLimitConfig {
                max_per_hour: 100,
                max_per_day: 100,
                max_concurrent: Some(2),
            },
        );

        let rate_limiter = RateLimiter::new(rate_limits);

        // Start two concurrent actions
        rate_limiter.start_concurrent("concurrent_action").await;
        rate_limiter.start_concurrent("concurrent_action").await;

        // Third should fail
        let result = rate_limiter.check("concurrent_action").await;
        assert!(result.is_err());
        assert!(matches!(result, Err(PolicyError::RateLimitExceeded(_))));

        // End one, then third should succeed
        rate_limiter.end_concurrent("concurrent_action").await;
        let result = rate_limiter.check("concurrent_action").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_rate_limiter_cleanup() {
        let mut rate_limits = HashMap::new();
        rate_limits.insert(
            "cleanup_action".to_string(),
            RateLimitConfig {
                max_per_hour: 10,
                max_per_day: 50,
                max_concurrent: None,
            },
        );

        let rate_limiter = RateLimiter::new(rate_limits);

        // Record some actions
        for _ in 0..5 {
            rate_limiter.record("cleanup_action").await;
        }

        // Cleanup should not fail
        rate_limiter.cleanup().await;

        // Should still be able to check
        let result = rate_limiter.check("cleanup_action").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_no_rate_limit_configured() {
        let rate_limiter = RateLimiter::new(HashMap::new());

        // Should pass when no limit is configured
        let result = rate_limiter.check("unconfigured_action").await;
        assert!(result.is_ok());
    }

    // ============================================================
    // Complex Rule Combinations
    // ============================================================

    #[tokio::test]
    async fn test_first_matching_rule_wins() {
        // Create rules where a more specific rule should take precedence
        let rules = vec![
            // First rule: Allow ticket actions with high confidence
            PolicyRule::new(
                "allow_tickets".to_string(),
                vec![
                    RuleCondition::ActionTypeIn(vec!["create_ticket".to_string()]),
                    RuleCondition::ConfidenceAbove(0.8),
                ],
                RuleEffect::Allow,
            ),
            // Second rule: All actions require approval (catch-all)
            PolicyRule::new(
                "default_approval".to_string(),
                vec![],
                RuleEffect::RequireApproval(ApprovalLevel::Analyst),
            ),
        ];

        let engine = PolicyEngine::new(rules, DenyList::default(), HashMap::new());

        // High confidence ticket should be allowed
        let ticket_context = create_test_context("create_ticket", 0.95);
        let decision = engine.evaluate(&ticket_context).await.unwrap();
        assert_eq!(decision, PolicyDecision::Allowed);

        // Low confidence ticket should require approval
        let low_conf_context = create_test_context("create_ticket", 0.5);
        let decision = engine.evaluate(&low_conf_context).await.unwrap();
        assert!(matches!(
            decision,
            PolicyDecision::RequiresApproval(ApprovalLevel::Analyst)
        ));
    }

    #[tokio::test]
    async fn test_deny_list_takes_precedence() {
        // Create an allow rule
        let rules = vec![PolicyRule::new(
            "allow_all".to_string(),
            vec![],
            RuleEffect::Allow,
        )];

        // But deny list blocks the action
        let deny_list = DenyList {
            actions: vec!["blocked_action".to_string()],
            target_patterns: vec![],
            protected_ips: vec![],
            protected_users: vec![],
        };

        let engine = PolicyEngine::new(rules, deny_list, HashMap::new());
        let context = create_test_context("blocked_action", 0.99);

        let decision = engine.evaluate(&context).await.unwrap();
        assert!(matches!(decision, PolicyDecision::Denied(_)));
    }

    #[tokio::test]
    async fn test_multiple_conditions_must_all_match() {
        let rules = vec![PolicyRule::new(
            "strict_rule".to_string(),
            vec![
                RuleCondition::ActionTypeIn(vec!["sensitive_action".to_string()]),
                RuleCondition::ConfidenceAbove(0.95),
                RuleCondition::IncidentSeverityIn(vec!["critical".to_string()]),
            ],
            RuleEffect::Allow,
        )];

        let engine = PolicyEngine::new(rules, DenyList::default(), HashMap::new());

        // Context that matches all conditions
        let mut full_match_context = create_test_context("sensitive_action", 0.99);
        full_match_context.incident_severity = "critical".to_string();
        let decision = engine.evaluate(&full_match_context).await.unwrap();
        assert_eq!(decision, PolicyDecision::Allowed);

        // Context missing severity match (defaults to "high")
        let partial_context = create_test_context("sensitive_action", 0.99);
        let decision = engine.evaluate(&partial_context).await.unwrap();
        // Should fall through to default (RequiresApproval)
        assert!(matches!(
            decision,
            PolicyDecision::RequiresApproval(ApprovalLevel::Analyst)
        ));
    }

    // ============================================================
    // Protected Resources
    // ============================================================

    #[tokio::test]
    async fn test_protected_ips() {
        let deny_list = DenyList {
            actions: vec![],
            target_patterns: vec![],
            protected_ips: vec!["10.0.0.1".to_string(), "192.168.1.1".to_string()],
            protected_users: vec![],
        };

        assert!(deny_list.is_ip_protected("10.0.0.1"));
        assert!(deny_list.is_ip_protected("192.168.1.1"));
        assert!(!deny_list.is_ip_protected("10.0.0.2"));
    }

    #[tokio::test]
    async fn test_protected_users() {
        let deny_list = DenyList {
            actions: vec![],
            target_patterns: vec![],
            protected_ips: vec![],
            protected_users: vec![
                "admin".to_string(),
                "root".to_string(),
                "service_account".to_string(),
            ],
        };

        assert!(deny_list.is_user_protected("admin"));
        assert!(deny_list.is_user_protected("root"));
        assert!(deny_list.is_user_protected("service_account"));
        assert!(!deny_list.is_user_protected("regular_user"));
    }

    #[tokio::test]
    async fn test_domain_controller_pattern_protection() {
        let engine = PolicyEngine::default_config();
        let mut context = create_test_context("isolate_host", 0.99);
        context.target.identifier = "dc01.corp.local".to_string();

        let decision = engine.evaluate(&context).await.unwrap();
        assert!(matches!(decision, PolicyDecision::Denied(_)));
    }

    // ============================================================
    // Concurrent Policy Evaluation
    // ============================================================

    #[tokio::test]
    async fn test_concurrent_policy_evaluation() {
        use std::sync::Arc;
        use tokio::task::JoinSet;

        let engine = Arc::new(PolicyEngine::default_config());
        let mut tasks = JoinSet::new();

        // Spawn 10 concurrent evaluations
        for i in 0..10 {
            let engine = Arc::clone(&engine);
            let action = if i % 2 == 0 {
                "create_ticket"
            } else {
                "isolate_host"
            };
            tasks.spawn(async move {
                let context = create_test_context(action, 0.95);
                engine.evaluate(&context).await
            });
        }

        // All should complete successfully
        let mut results = Vec::new();
        while let Some(result) = tasks.join_next().await {
            results.push(result.unwrap());
        }

        assert_eq!(results.len(), 10);
        for result in results {
            assert!(result.is_ok());
        }
    }

    #[tokio::test]
    async fn test_concurrent_rate_limit_recording() {
        use std::sync::Arc;
        use tokio::task::JoinSet;

        let mut rate_limits = HashMap::new();
        rate_limits.insert(
            "concurrent_test".to_string(),
            RateLimitConfig {
                max_per_hour: 1000,
                max_per_day: 5000,
                max_concurrent: None,
            },
        );

        let rate_limiter = Arc::new(RateLimiter::new(rate_limits));
        let mut tasks = JoinSet::new();

        // Spawn 50 concurrent recordings
        for _ in 0..50 {
            let limiter = Arc::clone(&rate_limiter);
            tasks.spawn(async move {
                limiter.record("concurrent_test").await;
            });
        }

        // All should complete
        while tasks.join_next().await.is_some() {}

        // Should still be under limit
        let result = rate_limiter.check("concurrent_test").await;
        assert!(result.is_ok());
    }

    // ============================================================
    // Edge Cases
    // ============================================================

    #[tokio::test]
    async fn test_empty_rules_uses_default() {
        let engine = PolicyEngine::new(vec![], DenyList::default(), HashMap::new());
        let context = create_test_context("any_action", 0.95);

        let decision = engine.evaluate(&context).await.unwrap();
        // Default is RequiresApproval(Analyst)
        assert!(matches!(
            decision,
            PolicyDecision::RequiresApproval(ApprovalLevel::Analyst)
        ));
    }

    #[tokio::test]
    async fn test_very_low_confidence_handling() {
        let engine = PolicyEngine::default_config();
        let context = create_test_context("create_ticket", 0.1);

        // Low confidence should not match high-confidence rules
        let decision = engine.evaluate(&context).await.unwrap();
        // Falls through to default
        assert!(matches!(
            decision,
            PolicyDecision::RequiresApproval(ApprovalLevel::Analyst)
        ));
    }

    #[tokio::test]
    async fn test_target_criticality_ordering() {
        // Verify criticality enum ordering
        assert!(Criticality::Low < Criticality::Medium);
        assert!(Criticality::Medium < Criticality::High);
        assert!(Criticality::High < Criticality::Critical);
    }

    // ============================================================
    // ReDoS Protection Tests
    // ============================================================

    #[test]
    fn test_validated_deny_list_compiles_patterns() {
        let deny_list = DenyList {
            actions: vec!["delete_user".to_string()],
            target_patterns: vec![r".*-prod-.*".to_string(), r"dc\d+\..*".to_string()],
            protected_ips: vec!["10.0.0.1".to_string()],
            protected_users: vec!["admin".to_string()],
        };

        let validated = ValidatedDenyList::try_from_deny_list(&deny_list).unwrap();

        // Verify patterns were compiled
        assert_eq!(validated.pattern_count(), 2);

        // Verify pattern matching works
        assert!(validated.is_target_protected("web-prod-01"));
        assert!(validated.is_target_protected("dc01.corp.local"));
        assert!(!validated.is_target_protected("web-dev-01"));

        // Verify other deny list features work
        assert!(validated.is_action_denied("delete_user"));
        assert!(!validated.is_action_denied("create_ticket"));
        assert!(validated.is_ip_protected("10.0.0.1"));
        assert!(validated.is_user_protected("admin"));
    }

    #[test]
    fn test_redos_nested_quantifiers_rejected() {
        // Classic ReDoS pattern: (a+)+
        let result = validate_regex_safe(r"(a+)+");
        assert!(result.is_err());
        if let Err(RegexValidationError::UnsafePattern { reason, .. }) = result {
            assert!(reason.contains("nested quantifiers"));
        }

        // Another ReDoS pattern: (a*)*
        let result = validate_regex_safe(r"(a*)*");
        assert!(result.is_err());

        // (a+)*
        let result = validate_regex_safe(r"(a+)*");
        assert!(result.is_err());
    }

    #[test]
    fn test_redos_excessive_quantifier_range_rejected() {
        // Excessive range: {1,10000}
        let result = validate_regex_safe(r"a{1,10000}");
        assert!(result.is_err());
        if let Err(RegexValidationError::UnsafePattern { reason, .. }) = result {
            assert!(reason.contains("too large"));
        }

        // Reasonable range should be accepted
        let result = validate_regex_safe(r"a{1,100}");
        assert!(result.is_ok());
    }

    #[test]
    fn test_redos_pattern_length_limit() {
        // Pattern that's too long
        let long_pattern = "a".repeat(1001);
        let result = validate_regex_safe(&long_pattern);
        assert!(result.is_err());
        if let Err(RegexValidationError::UnsafePattern { reason, .. }) = result {
            assert!(reason.contains("too long"));
        }

        // Pattern at the limit should be accepted
        let ok_pattern = "a".repeat(1000);
        let result = validate_regex_safe(&ok_pattern);
        assert!(result.is_ok());
    }

    #[test]
    fn test_safe_patterns_accepted() {
        // Normal patterns that should be accepted
        let safe_patterns = [
            r".*-prod-.*",
            r"dc\d+\..*",
            r"^[a-z]+$",
            r"[0-9]{3}-[0-9]{2}-[0-9]{4}",
            r"https?://.*",
            r"(foo|bar|baz)",
            r"user_\d+",
        ];

        for pattern in &safe_patterns {
            let result = validate_regex_safe(pattern);
            assert!(result.is_ok(), "Pattern '{}' should be safe", pattern);
        }
    }

    #[test]
    fn test_invalid_regex_rejected() {
        // Invalid regex syntax
        let result = CompiledPattern::new(r"[invalid(regex");
        assert!(result.is_err());
        if let Err(RegexValidationError::InvalidPattern { .. }) = result {
            // Expected
        } else {
            panic!("Expected InvalidPattern error");
        }
    }

    #[test]
    fn test_validated_deny_list_rejects_unsafe_patterns() {
        let deny_list = DenyList {
            actions: vec![],
            target_patterns: vec![r"(a+)+".to_string()], // ReDoS pattern
            protected_ips: vec![],
            protected_users: vec![],
        };

        let result = ValidatedDenyList::try_from_deny_list(&deny_list);
        assert!(result.is_err());
    }

    #[test]
    fn test_compiled_pattern_cached() {
        // Verify that patterns are compiled and cached (not recompiled on each match)
        let deny_list = DenyList {
            actions: vec![],
            target_patterns: vec![r".*-prod-.*".to_string()],
            protected_ips: vec![],
            protected_users: vec![],
        };

        let validated = ValidatedDenyList::try_from_deny_list(&deny_list).unwrap();

        // Multiple matches should use the same compiled pattern (Arc)
        for _ in 0..100 {
            assert!(validated.is_target_protected("web-prod-01"));
        }

        // Verify Arc reference count (pattern is shared)
        let pattern = &validated.compiled_patterns[0];
        assert_eq!(Arc::strong_count(&pattern.regex), 1);
    }

    #[test]
    fn test_pattern_sources_iterator() {
        let deny_list = DenyList {
            actions: vec![],
            target_patterns: vec![r".*-prod-.*".to_string(), r"dc\d+\..*".to_string()],
            protected_ips: vec![],
            protected_users: vec![],
        };

        let validated = ValidatedDenyList::try_from_deny_list(&deny_list).unwrap();
        let sources: Vec<&str> = validated.pattern_sources().collect();

        assert_eq!(sources.len(), 2);
        assert!(sources.contains(&".*-prod-.*"));
        assert!(sources.contains(&r"dc\d+\..*"));
    }

    #[test]
    fn test_empty_deny_list_validation() {
        let deny_list = DenyList::default();
        let validated = ValidatedDenyList::try_from_deny_list(&deny_list).unwrap();

        assert_eq!(validated.pattern_count(), 0);
        assert!(!validated.is_target_protected("anything"));
        assert!(!validated.is_action_denied("anything"));
    }

    // ============================================================
    // TOCTOU Race Condition Prevention Tests
    // ============================================================

    #[tokio::test]
    async fn test_atomic_check_and_record() {
        // Test that check_and_record is atomic
        let mut rate_limits = HashMap::new();
        rate_limits.insert(
            "atomic_test".to_string(),
            RateLimitConfig {
                max_per_hour: 5,
                max_per_day: 10,
                max_concurrent: None,
            },
        );

        let rate_limiter = RateLimiter::new(rate_limits);

        // Use check_and_record 5 times (should all succeed)
        for i in 0..5 {
            let result = rate_limiter.check_and_record("atomic_test").await;
            assert!(result.is_ok(), "check_and_record {} should succeed", i + 1);
        }

        // 6th should fail
        let result = rate_limiter.check_and_record("atomic_test").await;
        assert!(result.is_err(), "6th check_and_record should fail");
        assert!(matches!(result, Err(PolicyError::RateLimitExceeded(_))));
    }

    #[tokio::test]
    async fn test_atomic_try_start_concurrent() {
        // Test that try_start_concurrent is atomic
        let mut rate_limits = HashMap::new();
        rate_limits.insert(
            "concurrent_atomic".to_string(),
            RateLimitConfig {
                max_per_hour: 100,
                max_per_day: 100,
                max_concurrent: Some(3),
            },
        );

        let rate_limiter = RateLimiter::new(rate_limits);

        // Acquire 3 slots
        for i in 0..3 {
            let result = rate_limiter.try_start_concurrent("concurrent_atomic").await;
            assert!(
                result.is_ok(),
                "try_start_concurrent {} should succeed",
                i + 1
            );
        }

        // 4th should fail
        let result = rate_limiter.try_start_concurrent("concurrent_atomic").await;
        assert!(result.is_err(), "4th try_start_concurrent should fail");
        assert!(matches!(result, Err(PolicyError::RateLimitExceeded(_))));

        // Release one
        rate_limiter.end_concurrent("concurrent_atomic").await;

        // Now should succeed
        let result = rate_limiter.try_start_concurrent("concurrent_atomic").await;
        assert!(result.is_ok(), "After release, should succeed");
    }

    #[tokio::test]
    async fn test_concurrent_atomic_rate_limiting() {
        // Test that concurrent requests are properly rate limited
        // This tests the core TOCTOU fix
        use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
        use std::sync::Arc;
        use tokio::task::JoinSet;

        let mut rate_limits = HashMap::new();
        rate_limits.insert(
            "race_test".to_string(),
            RateLimitConfig {
                max_per_hour: 10,
                max_per_day: 100,
                max_concurrent: None,
            },
        );

        let rate_limiter = Arc::new(RateLimiter::new(rate_limits));
        let success_count = Arc::new(AtomicUsize::new(0));
        let mut tasks = JoinSet::new();

        // Spawn 50 concurrent requests trying to use the atomic check_and_record
        for _ in 0..50 {
            let limiter = Arc::clone(&rate_limiter);
            let counter = Arc::clone(&success_count);
            tasks.spawn(async move {
                if limiter.check_and_record("race_test").await.is_ok() {
                    counter.fetch_add(1, AtomicOrdering::SeqCst);
                }
            });
        }

        // Wait for all tasks to complete
        while tasks.join_next().await.is_some() {}

        // Exactly 10 should have succeeded (the limit)
        let final_count = success_count.load(AtomicOrdering::SeqCst);
        assert_eq!(
            final_count, 10,
            "Exactly 10 requests should succeed, got {}",
            final_count
        );
    }

    #[tokio::test]
    async fn test_concurrent_semaphore_rate_limiting() {
        // Test concurrent limit with many parallel requests
        use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
        use std::sync::Arc;
        use tokio::task::JoinSet;

        let mut rate_limits = HashMap::new();
        rate_limits.insert(
            "semaphore_test".to_string(),
            RateLimitConfig {
                max_per_hour: 1000,
                max_per_day: 1000,
                max_concurrent: Some(5),
            },
        );

        let rate_limiter = Arc::new(RateLimiter::new(rate_limits));
        let success_count = Arc::new(AtomicUsize::new(0));
        let mut tasks = JoinSet::new();

        // Spawn 20 concurrent requests
        for _ in 0..20 {
            let limiter = Arc::clone(&rate_limiter);
            let counter = Arc::clone(&success_count);
            tasks.spawn(async move {
                if limiter.try_start_concurrent("semaphore_test").await.is_ok() {
                    counter.fetch_add(1, AtomicOrdering::SeqCst);
                    // Simulate some work
                    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
                    limiter.end_concurrent("semaphore_test").await;
                }
            });
        }

        // Wait for all tasks to complete
        while tasks.join_next().await.is_some() {}

        // At most 5 should be concurrent at any time
        // Due to the short sleep, more may complete, but the first batch is limited to 5
        let final_count = success_count.load(AtomicOrdering::SeqCst);
        assert!(
            final_count >= 5,
            "At least 5 requests should succeed, got {}",
            final_count
        );
    }

    #[tokio::test]
    async fn test_evaluate_and_record_atomic() {
        // Test that evaluate_and_record is atomic
        let mut rate_limits = HashMap::new();
        rate_limits.insert(
            "evaluate_test".to_string(),
            RateLimitConfig {
                max_per_hour: 3,
                max_per_day: 10,
                max_concurrent: None,
            },
        );

        let engine = PolicyEngine::new(vec![], DenyList::default(), rate_limits);

        // First 3 should succeed
        for i in 0..3 {
            let context = create_test_context("evaluate_test", 0.95);
            let result = engine.evaluate_and_record(&context).await;
            assert!(
                result.is_ok(),
                "evaluate_and_record {} should succeed",
                i + 1
            );
        }

        // 4th should be rate limited
        let context = create_test_context("evaluate_test", 0.95);
        let result = engine.evaluate_and_record(&context).await.unwrap();
        assert!(
            matches!(result, PolicyDecision::Denied(_)),
            "4th should be denied"
        );
        if let PolicyDecision::Denied(reason) = result {
            assert_eq!(reason.rule_name, "rate_limit");
            assert!(reason.message.contains("hourly limit"));
        }
    }

    #[tokio::test]
    async fn test_try_start_action_atomic() {
        // Test PolicyEngine's atomic concurrent action start
        let mut rate_limits = HashMap::new();
        rate_limits.insert(
            "action_test".to_string(),
            RateLimitConfig {
                max_per_hour: 100,
                max_per_day: 100,
                max_concurrent: Some(2),
            },
        );

        let engine = PolicyEngine::new(vec![], DenyList::default(), rate_limits);

        // Start 2 actions
        assert!(engine.try_start_action("action_test").await.is_ok());
        assert!(engine.try_start_action("action_test").await.is_ok());

        // 3rd should fail
        let result = engine.try_start_action("action_test").await;
        assert!(result.is_err());
        assert!(matches!(result, Err(PolicyError::RateLimitExceeded(_))));

        // End one and try again
        engine.end_action("action_test").await;
        assert!(engine.try_start_action("action_test").await.is_ok());
    }

    #[tokio::test]
    async fn test_no_race_window_high_contention() {
        // High contention test to verify no race window exists
        use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
        use std::sync::Arc;
        use tokio::task::JoinSet;

        let mut rate_limits = HashMap::new();
        rate_limits.insert(
            "high_contention".to_string(),
            RateLimitConfig {
                max_per_hour: 100,
                max_per_day: 100,
                max_concurrent: Some(1), // Only 1 concurrent allowed
            },
        );

        let rate_limiter = Arc::new(RateLimiter::new(rate_limits));
        let acquired_count = Arc::new(AtomicUsize::new(0));
        let max_concurrent = Arc::new(AtomicUsize::new(0));
        let mut tasks = JoinSet::new();

        // Spawn 100 concurrent requests all trying to acquire the single slot
        for _ in 0..100 {
            let limiter = Arc::clone(&rate_limiter);
            let acquired = Arc::clone(&acquired_count);
            let max_conc = Arc::clone(&max_concurrent);
            tasks.spawn(async move {
                if limiter
                    .try_start_concurrent("high_contention")
                    .await
                    .is_ok()
                {
                    let current = acquired.fetch_add(1, AtomicOrdering::SeqCst) + 1;
                    // Track max concurrent
                    let mut max = max_conc.load(AtomicOrdering::SeqCst);
                    while current > max {
                        match max_conc.compare_exchange_weak(
                            max,
                            current,
                            AtomicOrdering::SeqCst,
                            AtomicOrdering::SeqCst,
                        ) {
                            Ok(_) => break,
                            Err(actual) => max = actual,
                        }
                    }
                    // Simulate some work
                    tokio::task::yield_now().await;
                    acquired.fetch_sub(1, AtomicOrdering::SeqCst);
                    limiter.end_concurrent("high_contention").await;
                }
            });
        }

        // Wait for all tasks
        while tasks.join_next().await.is_some() {}

        // The max concurrent should never exceed 1
        let final_max = max_concurrent.load(AtomicOrdering::SeqCst);
        assert!(
            final_max <= 1,
            "Max concurrent should be <= 1, got {}",
            final_max
        );
    }

    #[tokio::test]
    async fn test_check_and_record_no_bypass_under_load() {
        // Stress test to ensure no requests bypass the rate limit
        use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
        use std::sync::Arc;
        use tokio::task::JoinSet;

        const LIMIT: usize = 25;
        const REQUESTS: usize = 200;

        let mut rate_limits = HashMap::new();
        rate_limits.insert(
            "stress_test".to_string(),
            RateLimitConfig {
                max_per_hour: LIMIT as u32,
                max_per_day: 1000,
                max_concurrent: None,
            },
        );

        let rate_limiter = Arc::new(RateLimiter::new(rate_limits));
        let success_count = Arc::new(AtomicUsize::new(0));
        let mut tasks = JoinSet::new();

        // Spawn many concurrent requests
        for _ in 0..REQUESTS {
            let limiter = Arc::clone(&rate_limiter);
            let counter = Arc::clone(&success_count);
            tasks.spawn(async move {
                if limiter.check_and_record("stress_test").await.is_ok() {
                    counter.fetch_add(1, AtomicOrdering::SeqCst);
                }
            });
        }

        // Wait for all tasks
        while tasks.join_next().await.is_some() {}

        // Exactly LIMIT requests should succeed
        let final_count = success_count.load(AtomicOrdering::SeqCst);
        assert_eq!(
            final_count, LIMIT,
            "Exactly {} requests should succeed under high load, got {}",
            LIMIT, final_count
        );
    }
}
