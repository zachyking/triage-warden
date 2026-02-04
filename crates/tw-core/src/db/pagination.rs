//! Pagination types and utilities for database queries.
//!
//! This module provides standardized pagination support across all repositories,
//! with configurable defaults and maximum limits for security and performance.

use serde::{Deserialize, Serialize};

/// Default number of items per page.
pub const DEFAULT_PAGE_SIZE: u32 = 50;

/// Maximum allowed items per page.
pub const MAX_PAGE_SIZE: u32 = 200;

/// Pagination options for database queries.
#[derive(Debug, Clone)]
pub struct Pagination {
    /// Page number (1-indexed).
    pub page: u32,
    /// Items per page.
    pub per_page: u32,
}

impl Default for Pagination {
    fn default() -> Self {
        Self {
            page: 1,
            per_page: DEFAULT_PAGE_SIZE,
        }
    }
}

impl Pagination {
    /// Creates a new Pagination with the specified page and per_page values.
    ///
    /// # Arguments
    /// * `page` - Page number (1-indexed). Values less than 1 are clamped to 1.
    /// * `per_page` - Items per page. Values are clamped to the range [1, MAX_PAGE_SIZE].
    pub fn new(page: u32, per_page: u32) -> Self {
        Self {
            page: page.max(1),
            per_page: per_page.clamp(1, MAX_PAGE_SIZE),
        }
    }

    /// Creates a Pagination from optional query parameters with defaults.
    ///
    /// # Arguments
    /// * `page` - Optional page number. Defaults to 1.
    /// * `per_page` - Optional items per page. Defaults to DEFAULT_PAGE_SIZE.
    pub fn from_query(page: Option<u32>, per_page: Option<u32>) -> Self {
        Self::new(page.unwrap_or(1), per_page.unwrap_or(DEFAULT_PAGE_SIZE))
    }

    /// Calculate SQL offset based on page and per_page.
    ///
    /// # Returns
    /// The offset value to use in LIMIT/OFFSET queries.
    pub fn offset(&self) -> u32 {
        (self.page.saturating_sub(1)) * self.per_page
    }

    /// Get limit (per_page).
    ///
    /// # Returns
    /// The limit value to use in LIMIT/OFFSET queries.
    pub fn limit(&self) -> u32 {
        self.per_page
    }

    /// Calculate total pages from a total item count.
    ///
    /// # Arguments
    /// * `total_items` - Total number of items matching the query.
    ///
    /// # Returns
    /// The total number of pages.
    pub fn total_pages(&self, total_items: u64) -> u32 {
        if total_items == 0 {
            return 1;
        }
        ((total_items as f64) / (self.per_page as f64)).ceil() as u32
    }
}

/// A paginated result containing items and pagination metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginatedResult<T> {
    /// The items on the current page.
    pub items: Vec<T>,
    /// Total number of items matching the query (across all pages).
    pub total: u64,
    /// Current page number (1-indexed).
    pub page: u32,
    /// Number of items per page.
    pub per_page: u32,
    /// Total number of pages.
    pub total_pages: u32,
}

impl<T> PaginatedResult<T> {
    /// Creates a new PaginatedResult.
    ///
    /// # Arguments
    /// * `items` - The items on the current page.
    /// * `total` - Total number of items matching the query.
    /// * `pagination` - The pagination parameters used for the query.
    pub fn new(items: Vec<T>, total: u64, pagination: &Pagination) -> Self {
        Self {
            items,
            total,
            page: pagination.page,
            per_page: pagination.per_page,
            total_pages: pagination.total_pages(total),
        }
    }

    /// Returns true if there are no items.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Returns the number of items on the current page.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Returns true if there is a next page.
    pub fn has_next_page(&self) -> bool {
        self.page < self.total_pages
    }

    /// Returns true if there is a previous page.
    pub fn has_previous_page(&self) -> bool {
        self.page > 1
    }

    /// Maps the items to a different type.
    ///
    /// # Arguments
    /// * `f` - A function to transform each item.
    ///
    /// # Returns
    /// A new PaginatedResult with transformed items.
    pub fn map<U, F>(self, f: F) -> PaginatedResult<U>
    where
        F: FnMut(T) -> U,
    {
        PaginatedResult {
            items: self.items.into_iter().map(f).collect(),
            total: self.total,
            page: self.page,
            per_page: self.per_page,
            total_pages: self.total_pages,
        }
    }

    /// Try to map the items to a different type, propagating errors.
    ///
    /// # Arguments
    /// * `f` - A fallible function to transform each item.
    ///
    /// # Returns
    /// A Result containing either the new PaginatedResult or an error.
    pub fn try_map<U, E, F>(self, f: F) -> Result<PaginatedResult<U>, E>
    where
        F: FnMut(T) -> Result<U, E>,
    {
        let items: Result<Vec<U>, E> = self.items.into_iter().map(f).collect();
        Ok(PaginatedResult {
            items: items?,
            total: self.total,
            page: self.page,
            per_page: self.per_page,
            total_pages: self.total_pages,
        })
    }
}

/// Filter for audit log pagination queries.
#[derive(Debug, Clone, Default)]
pub struct AuditLogFilter {
    /// Filter by tenant (required for multi-tenant queries).
    pub tenant_id: Option<uuid::Uuid>,
    /// Filter by incident ID.
    pub incident_id: Option<uuid::Uuid>,
    /// Filter by actor.
    pub actor: Option<String>,
    /// Filter by action type (as string).
    pub action: Option<String>,
    /// Filter by minimum created_at timestamp.
    pub since: Option<chrono::DateTime<chrono::Utc>>,
    /// Filter by maximum created_at timestamp.
    pub until: Option<chrono::DateTime<chrono::Utc>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pagination_default() {
        let p = Pagination::default();
        assert_eq!(p.page, 1);
        assert_eq!(p.per_page, DEFAULT_PAGE_SIZE);
        assert_eq!(p.offset(), 0);
        assert_eq!(p.limit(), DEFAULT_PAGE_SIZE);
    }

    #[test]
    fn test_pagination_new() {
        let p = Pagination::new(3, 25);
        assert_eq!(p.page, 3);
        assert_eq!(p.per_page, 25);
        assert_eq!(p.offset(), 50);
        assert_eq!(p.limit(), 25);
    }

    #[test]
    fn test_pagination_clamps_values() {
        // Page 0 should become 1
        let p = Pagination::new(0, 50);
        assert_eq!(p.page, 1);

        // per_page over max should be clamped
        let p = Pagination::new(1, 500);
        assert_eq!(p.per_page, MAX_PAGE_SIZE);

        // per_page 0 should become 1
        let p = Pagination::new(1, 0);
        assert_eq!(p.per_page, 1);
    }

    #[test]
    fn test_pagination_from_query() {
        let p = Pagination::from_query(None, None);
        assert_eq!(p.page, 1);
        assert_eq!(p.per_page, DEFAULT_PAGE_SIZE);

        let p = Pagination::from_query(Some(5), Some(100));
        assert_eq!(p.page, 5);
        assert_eq!(p.per_page, 100);
    }

    #[test]
    fn test_pagination_total_pages() {
        let p = Pagination::new(1, 10);

        assert_eq!(p.total_pages(0), 1);
        assert_eq!(p.total_pages(5), 1);
        assert_eq!(p.total_pages(10), 1);
        assert_eq!(p.total_pages(11), 2);
        assert_eq!(p.total_pages(100), 10);
        assert_eq!(p.total_pages(101), 11);
    }

    #[test]
    fn test_paginated_result_new() {
        let items = vec![1, 2, 3, 4, 5];
        let pagination = Pagination::new(1, 5);
        let result = PaginatedResult::new(items, 15, &pagination);

        assert_eq!(result.len(), 5);
        assert_eq!(result.total, 15);
        assert_eq!(result.page, 1);
        assert_eq!(result.per_page, 5);
        assert_eq!(result.total_pages, 3);
        assert!(result.has_next_page());
        assert!(!result.has_previous_page());
    }

    #[test]
    fn test_paginated_result_last_page() {
        let items = vec![1, 2, 3];
        let pagination = Pagination::new(3, 5);
        let result = PaginatedResult::new(items, 13, &pagination);

        assert_eq!(result.len(), 3);
        assert_eq!(result.total, 13);
        assert_eq!(result.page, 3);
        assert_eq!(result.total_pages, 3);
        assert!(!result.has_next_page());
        assert!(result.has_previous_page());
    }

    #[test]
    fn test_paginated_result_empty() {
        let items: Vec<i32> = vec![];
        let pagination = Pagination::default();
        let result = PaginatedResult::new(items, 0, &pagination);

        assert!(result.is_empty());
        assert_eq!(result.total, 0);
        assert_eq!(result.total_pages, 1);
        assert!(!result.has_next_page());
        assert!(!result.has_previous_page());
    }

    #[test]
    fn test_paginated_result_map() {
        let items = vec![1, 2, 3];
        let pagination = Pagination::new(1, 10);
        let result = PaginatedResult::new(items, 3, &pagination);

        let mapped = result.map(|x| x * 2);
        assert_eq!(mapped.items, vec![2, 4, 6]);
        assert_eq!(mapped.total, 3);
        assert_eq!(mapped.page, 1);
    }

    #[test]
    fn test_paginated_result_try_map() {
        let items = vec![1, 2, 3];
        let pagination = Pagination::new(1, 10);
        let result = PaginatedResult::new(items, 3, &pagination);

        let mapped: Result<PaginatedResult<i32>, &str> = result.try_map(|x| {
            if x > 0 {
                Ok(x * 2)
            } else {
                Err("negative value")
            }
        });

        assert!(mapped.is_ok());
        let mapped = mapped.unwrap();
        assert_eq!(mapped.items, vec![2, 4, 6]);
    }
}
