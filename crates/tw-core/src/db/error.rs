//! Database error types.

use crate::crypto::CryptoError;
use thiserror::Error;

/// Errors that can occur during database operations.
#[derive(Error, Debug)]
pub enum DbError {
    /// Database connection error.
    #[error("Database connection error: {0}")]
    Connection(String),

    /// Query execution error.
    #[error("Query error: {0}")]
    Query(String),

    /// Record not found.
    #[error("Record not found: {entity} with id {id}")]
    NotFound { entity: String, id: String },

    /// Constraint violation (e.g., unique constraint).
    #[error("Constraint violation: {0}")]
    Constraint(String),

    /// Serialization/deserialization error.
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Migration error.
    #[error("Migration error: {0}")]
    Migration(String),

    /// Transaction error.
    #[error("Transaction error: {0}")]
    Transaction(String),

    /// Pool exhausted.
    #[error("Connection pool exhausted")]
    PoolExhausted,

    /// Invalid configuration.
    #[error("Invalid database configuration: {0}")]
    Configuration(String),

    /// Cryptographic operation error (e.g., encryption/decryption failure).
    #[error("Cryptographic error: {0}")]
    Crypto(String),
}

impl From<CryptoError> for DbError {
    fn from(err: CryptoError) -> Self {
        DbError::Crypto(err.to_string())
    }
}

#[cfg(feature = "database")]
impl From<sqlx::Error> for DbError {
    fn from(err: sqlx::Error) -> Self {
        match err {
            sqlx::Error::RowNotFound => DbError::NotFound {
                entity: "unknown".to_string(),
                id: "unknown".to_string(),
            },
            sqlx::Error::Database(db_err) => {
                if db_err.is_unique_violation() {
                    DbError::Constraint(db_err.message().to_string())
                } else {
                    DbError::Query(db_err.message().to_string())
                }
            }
            sqlx::Error::PoolTimedOut => DbError::PoolExhausted,
            sqlx::Error::Configuration(msg) => DbError::Configuration(msg.to_string()),
            _ => DbError::Query(err.to_string()),
        }
    }
}

#[cfg(feature = "database")]
impl From<sqlx::migrate::MigrateError> for DbError {
    fn from(err: sqlx::migrate::MigrateError) -> Self {
        DbError::Migration(err.to_string())
    }
}

impl From<serde_json::Error> for DbError {
    fn from(err: serde_json::Error) -> Self {
        DbError::Serialization(err.to_string())
    }
}
