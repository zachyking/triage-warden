//! Logging infrastructure for Triage Warden.
//!
//! This module provides structured logging using the tracing ecosystem.

use tracing::Level;
use tracing_subscriber::{
    fmt::{self, format::FmtSpan},
    layer::SubscriberExt,
    util::SubscriberInitExt,
    EnvFilter,
};

/// Logging configuration.
#[derive(Debug, Clone)]
pub struct LoggingConfig {
    /// Log level.
    pub level: Level,
    /// Whether to use JSON format.
    pub json_format: bool,
    /// Whether to include span events.
    pub include_spans: bool,
    /// Whether to include file/line info.
    pub include_location: bool,
    /// Whether to include thread IDs.
    pub include_thread_ids: bool,
    /// Whether to include target (module path).
    pub include_target: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: Level::INFO,
            json_format: false,
            include_spans: true,
            include_location: true,
            include_thread_ids: false,
            include_target: true,
        }
    }
}

impl LoggingConfig {
    /// Creates a development configuration with more verbose output.
    pub fn development() -> Self {
        Self {
            level: Level::DEBUG,
            json_format: false,
            include_spans: true,
            include_location: true,
            include_thread_ids: true,
            include_target: true,
        }
    }

    /// Creates a production configuration with JSON output.
    pub fn production() -> Self {
        Self {
            level: Level::INFO,
            json_format: true,
            include_spans: false,
            include_location: false,
            include_thread_ids: false,
            include_target: true,
        }
    }
}

/// Initializes the logging system with default configuration.
pub fn init_logging() {
    init_logging_with_config(LoggingConfig::default());
}

/// Initializes the logging system with the given configuration.
pub fn init_logging_with_config(config: LoggingConfig) {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new(format!(
            "tw_core={},tw_policy={},tw_connectors={},tw_actions={},tw_cli={}",
            config.level, config.level, config.level, config.level, config.level
        ))
    });

    let span_events = if config.include_spans {
        FmtSpan::NEW | FmtSpan::CLOSE
    } else {
        FmtSpan::NONE
    };

    if config.json_format {
        let fmt_layer = fmt::layer()
            .json()
            .with_span_events(span_events)
            .with_file(config.include_location)
            .with_line_number(config.include_location)
            .with_thread_ids(config.include_thread_ids)
            .with_target(config.include_target);

        tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt_layer)
            .init();
    } else {
        let fmt_layer = fmt::layer()
            .with_span_events(span_events)
            .with_file(config.include_location)
            .with_line_number(config.include_location)
            .with_thread_ids(config.include_thread_ids)
            .with_target(config.include_target);

        tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt_layer)
            .init();
    }
}

/// Creates a span for incident processing.
#[macro_export]
macro_rules! incident_span {
    ($incident_id:expr) => {
        tracing::info_span!("incident", incident_id = %$incident_id)
    };
    ($incident_id:expr, $($field:tt)*) => {
        tracing::info_span!("incident", incident_id = %$incident_id, $($field)*)
    };
}

/// Creates a span for action execution.
#[macro_export]
macro_rules! action_span {
    ($action_name:expr, $incident_id:expr) => {
        tracing::info_span!("action", action = %$action_name, incident_id = %$incident_id)
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = LoggingConfig::default();
        assert_eq!(config.level, Level::INFO);
        assert!(!config.json_format);
    }

    #[test]
    fn test_production_config() {
        let config = LoggingConfig::production();
        assert_eq!(config.level, Level::INFO);
        assert!(config.json_format);
    }

    #[test]
    fn test_development_config() {
        let config = LoggingConfig::development();
        assert_eq!(config.level, Level::DEBUG);
        assert!(!config.json_format);
    }
}
