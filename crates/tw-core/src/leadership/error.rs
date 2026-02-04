//! Error types for leader election.
//!
//! This module defines the error types that can occur during leader election
//! operations such as acquiring, renewing, or releasing leases.

use thiserror::Error;

/// Errors that can occur during leader election operations.
#[derive(Error, Debug, Clone)]
pub enum LeaderElectionError {
    /// The lease is already held by another instance.
    #[error("Lease for resource '{resource}' is already held by '{holder_id}'")]
    AlreadyHeld {
        /// The resource that was contested.
        resource: String,
        /// The ID of the current holder.
        holder_id: String,
    },

    /// The lease has expired and cannot be renewed.
    #[error("Lease for resource '{resource}' has expired")]
    LeaseExpired {
        /// The resource whose lease expired.
        resource: String,
    },

    /// The caller is not the leader for the specified resource.
    #[error("Not the leader for resource '{resource}'")]
    NotLeader {
        /// The resource for which leadership was expected.
        resource: String,
    },

    /// A connection error occurred while communicating with the backend.
    #[error("Connection error: {message}")]
    Connection {
        /// Description of the connection error.
        message: String,
    },

    /// An unknown or internal error occurred.
    #[error("Unknown error: {message}")]
    Unknown {
        /// Description of the error.
        message: String,
    },
}

impl LeaderElectionError {
    /// Creates an `AlreadyHeld` error.
    pub fn already_held(resource: impl Into<String>, holder_id: impl Into<String>) -> Self {
        Self::AlreadyHeld {
            resource: resource.into(),
            holder_id: holder_id.into(),
        }
    }

    /// Creates a `LeaseExpired` error.
    pub fn lease_expired(resource: impl Into<String>) -> Self {
        Self::LeaseExpired {
            resource: resource.into(),
        }
    }

    /// Creates a `NotLeader` error.
    pub fn not_leader(resource: impl Into<String>) -> Self {
        Self::NotLeader {
            resource: resource.into(),
        }
    }

    /// Creates a `Connection` error.
    pub fn connection(message: impl Into<String>) -> Self {
        Self::Connection {
            message: message.into(),
        }
    }

    /// Creates an `Unknown` error.
    pub fn unknown(message: impl Into<String>) -> Self {
        Self::Unknown {
            message: message.into(),
        }
    }

    /// Returns `true` if this error indicates the lease is held by another instance.
    pub fn is_already_held(&self) -> bool {
        matches!(self, Self::AlreadyHeld { .. })
    }

    /// Returns `true` if this error indicates the lease has expired.
    pub fn is_lease_expired(&self) -> bool {
        matches!(self, Self::LeaseExpired { .. })
    }

    /// Returns `true` if this error indicates the caller is not the leader.
    pub fn is_not_leader(&self) -> bool {
        matches!(self, Self::NotLeader { .. })
    }

    /// Returns `true` if this is a connection error.
    pub fn is_connection(&self) -> bool {
        matches!(self, Self::Connection { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_already_held_error() {
        let err = LeaderElectionError::already_held("scheduler", "instance-1");
        assert!(err.is_already_held());
        assert!(!err.is_lease_expired());
        assert!(err.to_string().contains("scheduler"));
        assert!(err.to_string().contains("instance-1"));
    }

    #[test]
    fn test_lease_expired_error() {
        let err = LeaderElectionError::lease_expired("metrics-aggregator");
        assert!(err.is_lease_expired());
        assert!(!err.is_not_leader());
        assert!(err.to_string().contains("metrics-aggregator"));
    }

    #[test]
    fn test_not_leader_error() {
        let err = LeaderElectionError::not_leader("cleanup-task");
        assert!(err.is_not_leader());
        assert!(!err.is_connection());
        assert!(err.to_string().contains("cleanup-task"));
    }

    #[test]
    fn test_connection_error() {
        let err = LeaderElectionError::connection("Redis connection refused");
        assert!(err.is_connection());
        assert!(err.to_string().contains("Redis connection refused"));
    }

    #[test]
    fn test_unknown_error() {
        let err = LeaderElectionError::unknown("Something went wrong");
        assert!(!err.is_already_held());
        assert!(!err.is_lease_expired());
        assert!(!err.is_not_leader());
        assert!(!err.is_connection());
        assert!(err.to_string().contains("Something went wrong"));
    }
}
