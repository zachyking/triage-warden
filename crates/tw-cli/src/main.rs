//! Triage Warden CLI
//!
//! Command-line interface for the Triage Warden SOC automation system.

use anyhow::Result;
use clap::{Parser, Subcommand};
use colored::Colorize;
use std::path::PathBuf;

mod api_client;
mod commands;
mod config;
mod validator;

use api_client::{ApiClient, ListIncidentsParams};
use commands::{run_server, ServeConfig};
use config::AppConfig;
use validator::ConfigValidator;

#[derive(Parser)]
#[command(name = "triage-warden")]
#[command(author = "Triage Warden Team")]
#[command(version)]
#[command(about = "AI-Augmented SOC for incident triage and response", long_about = None)]
struct Cli {
    /// Configuration file path
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Enable verbose output
    #[arg(short, long)]
    verbose: bool,

    /// Output format (text, json)
    #[arg(long, default_value = "text")]
    format: OutputFormat,

    /// API server URL (for remote commands)
    #[arg(long, default_value = "http://localhost:8080")]
    api_url: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum OutputFormat {
    Text,
    Json,
}

impl std::str::FromStr for OutputFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "text" => Ok(OutputFormat::Text),
            "json" => Ok(OutputFormat::Json),
            _ => Err(format!("Invalid output format: {}", s)),
        }
    }
}

#[derive(Subcommand)]
enum Commands {
    /// Start the API server
    Serve {
        /// Port to listen on
        #[arg(short, long, default_value = "8080")]
        port: u16,

        /// Host to bind to
        #[arg(long, default_value = "0.0.0.0")]
        host: String,

        /// Database URL (sqlite:// or postgres://)
        #[arg(short, long, default_value = "sqlite://triage-warden.db?mode=rwc")]
        database: String,

        /// Disable Swagger UI
        #[arg(long)]
        no_swagger: bool,

        /// Validate configuration and exit without starting the server
        #[arg(long)]
        validate_only: bool,
    },

    /// Start the Triage Warden daemon
    Start {
        /// Run in foreground (don't daemonize)
        #[arg(short, long)]
        foreground: bool,
    },

    /// Stop the running daemon
    Stop,

    /// Show daemon status
    Status,

    /// Validate configuration
    Validate {
        /// Configuration file to validate
        #[arg(short, long)]
        config: Option<PathBuf>,
    },

    /// Show current configuration
    Config {
        /// Show secrets (redacted by default)
        #[arg(long)]
        show_secrets: bool,
    },

    /// Manage incidents
    Incident {
        #[command(subcommand)]
        action: IncidentCommands,
    },

    /// Manage connectors
    Connector {
        #[command(subcommand)]
        action: ConnectorCommands,
    },

    /// Manage actions
    Action {
        #[command(subcommand)]
        action: ActionCommands,
    },

    /// View metrics and KPIs
    Metrics,

    /// Test the system with a sample alert
    Test {
        /// Alert type (phishing, malware, suspicious_login)
        #[arg(short, long, default_value = "phishing")]
        alert_type: String,

        /// Dry run (don't execute actions)
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Subcommand)]
enum IncidentCommands {
    /// List incidents
    List {
        /// Filter by status
        #[arg(short, long)]
        status: Option<String>,

        /// Maximum number of incidents to show
        #[arg(short, long, default_value = "20")]
        limit: usize,
    },

    /// Show incident details
    Show {
        /// Incident ID
        id: String,
    },

    /// Update incident status
    Update {
        /// Incident ID
        id: String,

        /// New status
        #[arg(short, long)]
        status: String,
    },
}

#[derive(Subcommand)]
enum ConnectorCommands {
    /// List configured connectors
    List,

    /// Test connector connectivity
    Test {
        /// Connector name
        name: String,
    },

    /// Show connector health
    Health,
}

#[derive(Subcommand)]
enum ActionCommands {
    /// List available actions
    List,

    /// Show action details
    Show {
        /// Action name
        name: String,
    },

    /// Execute an action (requires confirmation)
    Execute {
        /// Action name
        name: String,

        /// Action parameters as JSON
        #[arg(short, long)]
        params: String,

        /// Skip confirmation
        #[arg(short, long)]
        yes: bool,

        /// Dry run
        #[arg(long)]
        dry_run: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let log_level = if cli.verbose {
        tracing::Level::DEBUG
    } else {
        tracing::Level::INFO
    };

    tw_observability::logging::init_logging_with_config(tw_observability::logging::LoggingConfig {
        level: log_level,
        json_format: cli.format == OutputFormat::Json,
        ..Default::default()
    });

    // Load configuration
    let config_path = cli.config.clone().unwrap_or_else(default_config_path);
    let config = AppConfig::load(&config_path).unwrap_or_else(|_| {
        if cli.verbose {
            eprintln!("Using default configuration (no config file found)");
        }
        AppConfig::default()
    });

    // Execute command
    match cli.command {
        Commands::Serve {
            port,
            host,
            database,
            no_swagger,
            validate_only,
        } => {
            cmd_serve(
                ServeConfig {
                    port,
                    host,
                    database_url: database,
                    enable_swagger: !no_swagger,
                    timeout_secs: 30,
                },
                config,
                validate_only,
            )
            .await
        }
        Commands::Start { foreground } => cmd_start(config, foreground).await,
        Commands::Stop => cmd_stop().await,
        Commands::Status => cmd_status(cli.format).await,
        Commands::Validate { config: cfg_path } => {
            cmd_validate(cfg_path.unwrap_or(config_path)).await
        }
        Commands::Config { show_secrets } => cmd_config(config, show_secrets, cli.format).await,
        Commands::Incident { action } => cmd_incident(action, cli.format, &cli.api_url).await,
        Commands::Connector { action } => cmd_connector(action, config, cli.format).await,
        Commands::Action { action } => cmd_action(action, config, cli.format).await,
        Commands::Metrics => cmd_metrics(cli.format, &cli.api_url).await,
        Commands::Test {
            alert_type,
            dry_run,
        } => cmd_test(config, &alert_type, dry_run).await,
    }
}

fn default_config_path() -> PathBuf {
    if let Some(dirs) = directories::ProjectDirs::from("com", "triage-warden", "triage-warden") {
        dirs.config_dir().join("config.yaml")
    } else {
        PathBuf::from("config/default.yaml")
    }
}

async fn cmd_serve(
    serve_config: ServeConfig,
    app_config: AppConfig,
    validate_only: bool,
) -> Result<()> {
    println!("{}", "Validating configuration...".cyan());

    // Run configuration validation
    let validation_result = ConfigValidator::validate(&app_config);
    validation_result.print();

    // If validate_only mode, exit after validation
    if validate_only {
        if validation_result.has_errors() {
            println!();
            println!(
                "{}",
                "Configuration validation failed. Fix the errors above before starting the server."
                    .red()
                    .bold()
            );
            std::process::exit(1);
        } else {
            println!();
            println!(
                "{}",
                "Configuration is valid. Server can be started."
                    .green()
                    .bold()
            );
            return Ok(());
        }
    }

    // If there are errors, refuse to start
    if validation_result.has_errors() {
        println!();
        println!(
            "{}",
            "Server startup aborted due to configuration errors. Fix the errors above and try again."
                .red()
                .bold()
        );
        std::process::exit(1);
    }

    println!();
    run_server(serve_config, app_config).await
}

async fn cmd_start(config: AppConfig, foreground: bool) -> Result<()> {
    println!("{}", "Starting Triage Warden...".green().bold());
    println!("Mode: {}", config.operation_mode);

    if !foreground {
        println!("Running in daemon mode (use --foreground to run in foreground)");
        // In a real implementation, this would daemonize the process
    }

    // Create orchestrator
    let orchestrator =
        tw_core::Orchestrator::with_config(tw_core::orchestrator::OrchestratorConfig {
            mode: match config.operation_mode.as_str() {
                "assisted" => tw_core::orchestrator::OperationMode::Assisted,
                "autonomous" => tw_core::orchestrator::OperationMode::Autonomous,
                _ => tw_core::orchestrator::OperationMode::Supervised,
            },
            ..Default::default()
        });

    // Start the orchestrator
    orchestrator.start().await?;

    println!("{}", "Triage Warden started successfully".green());
    println!("Event bus listening for alerts...");

    // In a real implementation, this would:
    // 1. Set up signal handlers for graceful shutdown
    // 2. Start alert ingestion from configured sources
    // 3. Run the main event loop

    // For now, just wait
    if foreground {
        println!("Press Ctrl+C to stop");
        tokio::signal::ctrl_c().await?;
        println!("\n{}", "Shutting down...".yellow());
        orchestrator.stop().await?;
    }

    Ok(())
}

async fn cmd_stop() -> Result<()> {
    println!("{}", "Stopping Triage Warden...".yellow());
    // In a real implementation, this would send a signal to the daemon
    println!("{}", "Triage Warden stopped".green());
    Ok(())
}

async fn cmd_status(format: OutputFormat) -> Result<()> {
    // In a real implementation, this would query the running daemon
    let status = serde_json::json!({
        "running": false,
        "version": env!("CARGO_PKG_VERSION"),
        "uptime": null,
        "incidents_in_progress": 0,
        "pending_approvals": 0,
    });

    if format == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&status)?);
    } else {
        println!("{}", "Triage Warden Status".bold());
        println!("─────────────────────");
        println!("Running: {}", "No".red());
        println!("Version: {}", env!("CARGO_PKG_VERSION"));
    }

    Ok(())
}

async fn cmd_validate(config_path: PathBuf) -> Result<()> {
    println!(
        "Validating configuration: {}",
        config_path.display().to_string().cyan()
    );

    // First, check if the file can be loaded
    let config = match AppConfig::load(&config_path) {
        Ok(config) => config,
        Err(e) => {
            println!("{}: {}", "Configuration file error".red().bold(), e);
            std::process::exit(1);
        }
    };

    // Run comprehensive validation
    let validation_result = ConfigValidator::validate(&config);
    validation_result.print();

    // Summary
    println!();
    println!("{}", "Configuration Summary".bold());
    println!("─────────────────────");
    println!("  Mode: {}", config.operation_mode);
    println!("  Connectors: {}", config.connectors.len());
    println!("  LLM Provider: {}", config.llm.provider);
    println!("  Database: {}", config.database.url);

    if validation_result.has_errors() {
        println!();
        println!(
            "{}",
            "Configuration validation failed. Fix the errors above."
                .red()
                .bold()
        );
        std::process::exit(1);
    } else if validation_result.has_warnings() {
        println!();
        println!(
            "{}",
            "Configuration is valid with warnings. Review the warnings above."
                .yellow()
                .bold()
        );
    } else {
        println!();
        println!("{}", "Configuration is valid.".green().bold());
    }

    Ok(())
}

async fn cmd_config(config: AppConfig, show_secrets: bool, format: OutputFormat) -> Result<()> {
    let display_config = if show_secrets {
        config
    } else {
        config.redact_secrets()
    };

    if format == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&display_config)?);
    } else {
        println!("{}", "Current Configuration".bold());
        println!("─────────────────────────");
        println!("Operation Mode: {}", display_config.operation_mode);
        println!("\nConnectors:");
        for (name, connector) in &display_config.connectors {
            println!(
                "  - {}: {} ({})",
                name, connector.connector_type, connector.enabled
            );
        }
    }

    Ok(())
}

async fn cmd_incident(action: IncidentCommands, format: OutputFormat, api_url: &str) -> Result<()> {
    let client = ApiClient::new(api_url)?;

    match action {
        IncidentCommands::List { status, limit } => {
            let params = ListIncidentsParams {
                status,
                per_page: Some(limit as u32),
                ..Default::default()
            };

            match client.list_incidents(&params).await {
                Ok(response) => {
                    if format == OutputFormat::Json {
                        println!("{}", serde_json::to_string_pretty(&response)?);
                    } else {
                        println!("{}", "Incidents".bold());
                        println!("─────────");
                        if response.data.is_empty() {
                            println!("No incidents found");
                        } else {
                            for incident in response.data {
                                let severity_color = match incident.severity.as_str() {
                                    "critical" => incident.severity.red(),
                                    "high" => incident.severity.yellow(),
                                    "medium" => incident.severity.cyan(),
                                    _ => incident.severity.white(),
                                };
                                println!(
                                    "  {} [{}] {} - {}",
                                    incident.id.to_string()[..8].cyan(),
                                    severity_color,
                                    incident.status,
                                    incident.title.unwrap_or_else(|| "Untitled".to_string())
                                );
                            }
                            println!();
                            println!(
                                "Page {}/{} ({} total)",
                                response.pagination.page,
                                response.pagination.total_pages,
                                response.pagination.total_items
                            );
                        }
                    }
                }
                Err(e) => {
                    println!("{}: {}", "Error".red(), e);
                    println!("Make sure the API server is running (triage-warden serve)");
                }
            }
        }
        IncidentCommands::Show { id } => match uuid::Uuid::parse_str(&id) {
            Ok(uuid) => match client.get_incident(uuid).await {
                Ok(incident) => {
                    if format == OutputFormat::Json {
                        println!("{}", serde_json::to_string_pretty(&incident)?);
                    } else {
                        println!("{} {}", "Incident:".bold(), incident.incident.id);
                        println!("─────────────────────────────────────────");
                        println!("  {} {}", "Status:".cyan(), incident.incident.status);
                        println!("  {} {}", "Severity:".cyan(), incident.incident.severity);
                        println!("  {} {}", "Source:".cyan(), incident.incident.source);
                        if let Some(title) = &incident.incident.title {
                            println!("  {} {}", "Title:".cyan(), title);
                        }
                        if let Some(verdict) = &incident.incident.verdict {
                            println!("  {} {}", "Verdict:".cyan(), verdict);
                        }
                        println!("  {} {}", "Created:".cyan(), incident.incident.created_at);
                        println!();
                        println!(
                            "{} ({})",
                            "Proposed Actions".bold(),
                            incident.proposed_actions.len()
                        );
                        for action in &incident.proposed_actions {
                            println!(
                                "  {} [{}] {} - {}",
                                action.id.to_string()[..8].cyan(),
                                action.approval_status,
                                action.action_type,
                                action.reason
                            );
                        }
                        println!();
                        println!("{} ({})", "Audit Log".bold(), incident.audit_log.len());
                        for entry in &incident.audit_log {
                            println!(
                                "  {} {} by {}",
                                entry.timestamp.format("%Y-%m-%d %H:%M:%S"),
                                entry.action,
                                entry.actor
                            );
                        }
                    }
                }
                Err(e) => {
                    println!("{}: {}", "Error".red(), e);
                }
            },
            Err(_) => {
                println!("{}: Invalid UUID format", "Error".red());
            }
        },
        IncidentCommands::Update { id, status } => {
            println!("Updating incident {} to status: {}", id.cyan(), status);
            println!("(not implemented - use API directly)");
        }
    }
    Ok(())
}

async fn cmd_connector(
    action: ConnectorCommands,
    config: AppConfig,
    _format: OutputFormat,
) -> Result<()> {
    match action {
        ConnectorCommands::List => {
            println!("{}", "Configured Connectors".bold());
            println!("─────────────────────");
            for (name, connector) in &config.connectors {
                let status = if connector.enabled {
                    "enabled".green()
                } else {
                    "disabled".red()
                };
                println!(
                    "  {} ({}) - {}",
                    name.cyan(),
                    connector.connector_type,
                    status
                );
            }
        }
        ConnectorCommands::Test { name } => {
            println!("Testing connector: {}", name.cyan());
            if let Some(connector) = config.connectors.get(&name) {
                println!("  Type: {}", connector.connector_type);
                println!("  Base URL: {}", connector.base_url);
                println!("  Status: {}", "Test not implemented".yellow());
            } else {
                println!("{}", "Connector not found".red());
            }
        }
        ConnectorCommands::Health => {
            println!("{}", "Connector Health".bold());
            println!("────────────────");
            for (name, connector) in &config.connectors {
                let health = if connector.enabled {
                    "Unknown (daemon not running)".yellow()
                } else {
                    "Disabled".red()
                };
                println!("  {}: {}", name, health);
            }
        }
    }
    Ok(())
}

async fn cmd_action(
    action: ActionCommands,
    _config: AppConfig,
    _format: OutputFormat,
) -> Result<()> {
    match action {
        ActionCommands::List => {
            println!("{}", "Available Actions".bold());
            println!("─────────────────");
            println!(
                "  {} - Isolate a host from the network",
                "isolate_host".cyan()
            );
            println!("  {} - Remove host isolation", "unisolate_host".cyan());
            println!("  {} - Disable a user account", "disable_user".cyan());
            println!("  {} - Create a ticket", "create_ticket".cyan());
            println!("  {} - Send a notification", "send_notification".cyan());
        }
        ActionCommands::Show { name } => {
            println!("Action: {}", name.cyan());
            println!("(action details not implemented)");
        }
        ActionCommands::Execute {
            name,
            params,
            yes,
            dry_run,
        } => {
            if !yes {
                println!(
                    "{}: Execute action '{}' with params: {}",
                    "Confirm".yellow(),
                    name,
                    params
                );
                println!("(use --yes to skip confirmation)");
                return Ok(());
            }

            if dry_run {
                println!("{}: Would execute action '{}'", "Dry run".yellow(), name);
            } else {
                println!("Executing action: {}", name.cyan());
                println!("(daemon not running)");
            }
        }
    }
    Ok(())
}

async fn cmd_metrics(format: OutputFormat, api_url: &str) -> Result<()> {
    let client = ApiClient::new(api_url)?;

    match client.metrics().await {
        Ok(metrics) => {
            if format == OutputFormat::Json {
                println!("{}", serde_json::to_string_pretty(&metrics)?);
            } else {
                println!("{}", "Triage Warden Metrics".bold());
                println!("─────────────────────");
                println!();
                println!("{}", "Incidents".bold());
                println!("  Total: {}", metrics.incidents.total);
                println!(
                    "  Created (last hour): {}",
                    metrics.incidents.created_last_hour
                );
                println!(
                    "  Resolved (last hour): {}",
                    metrics.incidents.resolved_last_hour
                );
                println!();
                println!("{}", "By Status".bold());
                for (status, count) in &metrics.incidents.by_status {
                    println!("  {}: {}", status, count);
                }
                println!();
                println!("{}", "Actions".bold());
                println!("  Total executed: {}", metrics.actions.total_executed);
                println!(
                    "  Success rate: {:.1}%",
                    metrics.actions.success_rate * 100.0
                );
                println!("  Pending approvals: {}", metrics.actions.pending_approvals);
                println!();
                println!("{}", "Performance".bold());
                if let Some(mttt) = metrics.performance.mean_time_to_triage_seconds {
                    println!("  Mean Time to Triage: {:.1}s", mttt);
                }
                if let Some(mttr) = metrics.performance.mean_time_to_respond_seconds {
                    println!("  Mean Time to Respond: {:.1}s", mttr);
                }
                if let Some(arr) = metrics.performance.auto_resolution_rate {
                    println!("  Auto-resolution Rate: {:.1}%", arr * 100.0);
                }
            }
        }
        Err(e) => {
            println!("{}: {}", "Error".red(), e);
            println!("Make sure the API server is running (triage-warden serve)");
        }
    }
    Ok(())
}

async fn cmd_test(_config: AppConfig, alert_type: &str, dry_run: bool) -> Result<()> {
    println!("{}", "Running Test".bold());
    println!("────────────");
    println!("Alert Type: {}", alert_type.cyan());
    println!("Dry Run: {}", dry_run);

    // Create a sample alert based on type
    let alert = match alert_type {
        "phishing" => tw_core::Alert {
            id: format!("test-{}", uuid::Uuid::new_v4()),
            source: tw_core::AlertSource::EmailSecurity("TestGateway".to_string()),
            alert_type: "suspected_phishing".to_string(),
            severity: tw_core::Severity::High,
            title: "Test Phishing Alert".to_string(),
            description: Some("This is a test phishing alert for validation".to_string()),
            data: serde_json::json!({
                "sender": "attacker@evil.com",
                "subject": "Urgent: Update your password",
                "recipient": "user@company.com",
                "urls": ["http://evil.com/phish"]
            }),
            timestamp: chrono::Utc::now(),
            tags: vec!["test".to_string(), "phishing".to_string()],
        },
        "malware" => tw_core::Alert {
            id: format!("test-{}", uuid::Uuid::new_v4()),
            source: tw_core::AlertSource::Edr("TestEDR".to_string()),
            alert_type: "malware_detected".to_string(),
            severity: tw_core::Severity::Critical,
            title: "Test Malware Alert".to_string(),
            description: Some("This is a test malware detection alert".to_string()),
            data: serde_json::json!({
                "hostname": "workstation-001",
                "file_hash": "44d88612fea8a8f36de82e1278abb02f",
                "file_path": "C:\\Users\\test\\malware.exe"
            }),
            timestamp: chrono::Utc::now(),
            tags: vec!["test".to_string(), "malware".to_string()],
        },
        _ => {
            println!("{}: Unknown alert type: {}", "Error".red(), alert_type);
            return Ok(());
        }
    };

    println!("\nCreated test alert:");
    println!("  ID: {}", alert.id);
    println!("  Source: {}", alert.source);
    println!("  Severity: {}", alert.severity);

    // Create orchestrator and process alert
    let orchestrator = tw_core::Orchestrator::new();

    if dry_run {
        println!(
            "\n{}: Would process alert through triage pipeline",
            "Dry run".yellow()
        );
    } else {
        println!("\nProcessing alert...");
        match orchestrator.process_alert(alert).await {
            Ok(incident_id) => {
                println!("{}", "Alert processed successfully".green());
                println!("Incident ID: {}", incident_id);
            }
            Err(e) => {
                println!("{}: {}", "Error processing alert".red(), e);
            }
        }
    }

    Ok(())
}
