//! Serve command - starts the API server.

use anyhow::{Context, Result};
use colored::Colorize;
use std::net::SocketAddr;
use std::time::Duration;

use tw_api::{ApiServer, ApiServerConfig, AppState};
use tw_core::db::{create_pool, run_migrations};
use tw_core::EventBus;

use crate::config::AppConfig;

/// Server configuration from CLI arguments.
#[derive(Debug, Clone)]
pub struct ServeConfig {
    /// Port to listen on.
    pub port: u16,
    /// Hostname to bind to.
    pub host: String,
    /// Database URL.
    pub database_url: String,
    /// Enable Swagger UI.
    pub enable_swagger: bool,
    /// Request timeout in seconds.
    pub timeout_secs: u64,
}

impl Default for ServeConfig {
    fn default() -> Self {
        Self {
            port: 8080,
            host: "0.0.0.0".to_string(),
            database_url: "sqlite://triage-warden.db?mode=rwc".to_string(),
            enable_swagger: true,
            timeout_secs: 30,
        }
    }
}

/// Runs the API server.
pub async fn run_server(config: ServeConfig, _app_config: AppConfig) -> Result<()> {
    println!("{} Starting Triage Warden API Server...", "[server]".cyan());

    // Create database connection pool
    println!("  {} Database: {}", "→".green(), config.database_url);
    let db_pool = create_pool(&config.database_url)
        .await
        .context("Failed to create database connection pool")?;

    println!("  {} Running migrations...", "→".green());
    run_migrations(&db_pool)
        .await
        .context("Failed to run database migrations")?;

    println!("  {} Migrations complete", "✓".green());

    // Create event bus
    let event_bus = EventBus::new(1024);

    // Create application state
    let state = AppState::new(db_pool, event_bus);

    // Build server config
    let bind_address: SocketAddr = format!("{}:{}", config.host, config.port)
        .parse()
        .context("Invalid bind address")?;

    let server_config = ApiServerConfig {
        bind_address,
        request_timeout: Duration::from_secs(config.timeout_secs),
        enable_swagger: config.enable_swagger,
        shutdown_timeout: Duration::from_secs(30),
        session_cookie_name: "tw_session".to_string(),
        session_expiry_seconds: 86400, // 24 hours
        session_secure: false,         // Allow HTTP for development
    };

    // Print startup info
    println!();
    println!("{}", "Triage Warden API Server".bold());
    println!("{}", "═".repeat(40));
    println!("  {} http://{}", "Address:".cyan(), bind_address);
    println!("  {} {}", "Database:".cyan(), config.database_url);

    if config.enable_swagger {
        println!(
            "  {} http://{}/swagger-ui",
            "Swagger UI:".cyan(),
            bind_address
        );
    }

    println!();
    println!("{}", "Endpoints:".bold());
    println!("  GET  /health                  - Health check");
    println!("  GET  /ready                   - Readiness probe");
    println!("  GET  /live                    - Liveness probe");
    println!("  GET  /api/incidents           - List incidents");
    println!("  GET  /api/incidents/:id       - Get incident");
    println!("  POST /api/incidents/:id/actions - Execute action");
    println!("  POST /api/incidents/:id/approve - Approve action");
    println!("  POST /api/webhooks/alerts     - Ingest alert");
    println!("  GET  /metrics                 - Prometheus metrics");
    println!();
    println!("Press {} to stop", "Ctrl+C".yellow());
    println!();

    // Create and run server
    let server = ApiServer::new(state, server_config);
    server.run().await.context("Server error")?;

    println!();
    println!("{} Server stopped", "[server]".cyan());

    Ok(())
}
