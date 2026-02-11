//! Triage Warden CLI
//!
//! Command-line interface for the Triage Warden SOC automation system.

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::path::PathBuf;
use std::process::Stdio;

mod api_client;
mod commands;
mod config;
mod validator;

use api_client::{ApiClient, ExecuteActionRequest, ListIncidentsParams};
use commands::{run_server, ServeConfig};
use config::{AppConfig, ConnectorConfig};
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
        Commands::Start { foreground } => cmd_start(config, foreground, &config_path).await,
        Commands::Stop => cmd_stop().await,
        Commands::Status => cmd_status(cli.format).await,
        Commands::Validate { config: cfg_path } => {
            cmd_validate(cfg_path.unwrap_or(config_path)).await
        }
        Commands::Config { show_secrets } => cmd_config(config, show_secrets, cli.format).await,
        Commands::Incident { action } => cmd_incident(action, cli.format, &cli.api_url).await,
        Commands::Connector { action } => cmd_connector(action, config, cli.format).await,
        Commands::Action { action } => cmd_action(action, config, cli.format, &cli.api_url).await,
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

const DAEMON_RUNTIME_DIR_ENV: &str = "TW_DAEMON_RUNTIME_DIR";
const DAEMON_STATE_FILE: &str = "daemon_state.json";
const DAEMON_LOG_FILE: &str = "daemon.log";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DaemonState {
    pid: u32,
    started_at: chrono::DateTime<chrono::Utc>,
    operation_mode: String,
    config_path: String,
}

fn daemon_runtime_dir() -> PathBuf {
    if let Ok(path) = std::env::var(DAEMON_RUNTIME_DIR_ENV) {
        let trimmed = path.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }

    if let Some(dirs) = directories::ProjectDirs::from("com", "triage-warden", "triage-warden") {
        return dirs.data_local_dir().join("runtime");
    }

    PathBuf::from(".triage-warden/runtime")
}

fn daemon_state_path() -> PathBuf {
    daemon_runtime_dir().join(DAEMON_STATE_FILE)
}

fn daemon_log_path() -> PathBuf {
    daemon_runtime_dir().join(DAEMON_LOG_FILE)
}

fn ensure_daemon_runtime_dir() -> Result<PathBuf> {
    let runtime_dir = daemon_runtime_dir();
    std::fs::create_dir_all(&runtime_dir).with_context(|| {
        format!(
            "Failed to create daemon runtime directory '{}'",
            runtime_dir.display()
        )
    })?;
    Ok(runtime_dir)
}

fn write_daemon_state(state: &DaemonState) -> Result<PathBuf> {
    let runtime_dir = ensure_daemon_runtime_dir()?;
    let state_path = runtime_dir.join(DAEMON_STATE_FILE);
    let serialized = serde_json::to_vec_pretty(state)
        .context("Failed to serialize daemon state for persistence")?;
    std::fs::write(&state_path, serialized).with_context(|| {
        format!(
            "Failed to write daemon state file '{}'",
            state_path.display()
        )
    })?;
    Ok(state_path)
}

fn read_daemon_state() -> Result<Option<DaemonState>> {
    let state_path = daemon_state_path();
    if !state_path.exists() {
        return Ok(None);
    }

    let bytes = std::fs::read(&state_path).with_context(|| {
        format!(
            "Failed to read daemon state file '{}'",
            state_path.display()
        )
    })?;
    let state = serde_json::from_slice::<DaemonState>(&bytes).map_err(|e| {
        anyhow!(
            "Failed to parse daemon state file '{}': {}",
            state_path.display(),
            e
        )
    })?;
    Ok(Some(state))
}

fn clear_daemon_state() -> Result<()> {
    let state_path = daemon_state_path();
    if state_path.exists() {
        std::fs::remove_file(&state_path).with_context(|| {
            format!(
                "Failed to remove daemon state file '{}'",
                state_path.display()
            )
        })?;
    }
    Ok(())
}

fn process_is_running(pid: u32) -> bool {
    std::process::Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "pid="])
        .output()
        .map(|output| {
            output.status.success() && !String::from_utf8_lossy(&output.stdout).trim().is_empty()
        })
        .unwrap_or(false)
}

fn signal_process(pid: u32, signal: &str) -> Result<()> {
    let status = std::process::Command::new("kill")
        .arg(signal)
        .arg(pid.to_string())
        .status()
        .with_context(|| format!("Failed to run kill command for pid {}", pid))?;

    if !status.success() {
        return Err(anyhow!(
            "Failed to send signal {} to daemon process {}",
            signal,
            pid
        ));
    }

    Ok(())
}

async fn wait_for_process_exit(pid: u32, timeout: std::time::Duration) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if !process_is_running(pid) {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    !process_is_running(pid)
}

#[cfg(unix)]
async fn wait_for_shutdown_signal() -> Result<&'static str> {
    use tokio::signal::unix::{signal, SignalKind};

    let mut sigterm =
        signal(SignalKind::terminate()).context("Failed to install SIGTERM handler")?;

    tokio::select! {
        _ = tokio::signal::ctrl_c() => Ok("ctrl_c"),
        _ = sigterm.recv() => Ok("sigterm"),
    }
}

#[cfg(not(unix))]
async fn wait_for_shutdown_signal() -> Result<&'static str> {
    tokio::signal::ctrl_c().await?;
    Ok("ctrl_c")
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

async fn cmd_start(config: AppConfig, foreground: bool, config_path: &PathBuf) -> Result<()> {
    println!("{}", "Starting Triage Warden...".green().bold());
    println!("Mode: {}", config.operation_mode);

    if let Some(existing) = read_daemon_state()? {
        if process_is_running(existing.pid) {
            println!(
                "{}: Daemon already running (pid: {})",
                "Info".yellow(),
                existing.pid
            );
            println!("Use `triage-warden status` to inspect or `triage-warden stop` to stop.");
            return Ok(());
        }

        println!(
            "{}: Found stale daemon state for pid {}, cleaning up.",
            "Warning".yellow(),
            existing.pid
        );
        clear_daemon_state()?;
    }

    if !foreground {
        println!("Running in daemon mode (use --foreground to run in foreground)");

        ensure_daemon_runtime_dir()?;
        let log_path = daemon_log_path();
        let log_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .with_context(|| format!("Failed to open daemon log file '{}'", log_path.display()))?;
        let stderr_log = log_file
            .try_clone()
            .context("Failed to duplicate daemon log file handle")?;

        let current_exe =
            std::env::current_exe().context("Failed to resolve current executable")?;
        let mut command = std::process::Command::new(current_exe);
        command
            .arg("--config")
            .arg(config_path)
            .arg("start")
            .arg("--foreground")
            .stdout(Stdio::from(log_file))
            .stderr(Stdio::from(stderr_log));

        let mut child = command.spawn().context("Failed to spawn daemon process")?;
        let child_pid = child.id();

        for _ in 0..20 {
            if let Some(state) = read_daemon_state()? {
                if state.pid == child_pid && process_is_running(state.pid) {
                    println!(
                        "{} (pid: {})",
                        "Triage Warden daemon started successfully".green(),
                        child_pid
                    );
                    println!("State file: {}", daemon_state_path().display());
                    println!("Logs: {}", log_path.display());
                    return Ok(());
                }
            }

            if let Some(status) = child
                .try_wait()
                .context("Failed to monitor daemon process startup")?
            {
                return Err(anyhow!(
                    "Daemon process exited during startup with status {}. Check logs at {}",
                    status,
                    log_path.display()
                ));
            }

            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }

        if process_is_running(child_pid) {
            println!(
                "{} (pid: {})",
                "Triage Warden daemon started".green(),
                child_pid
            );
            println!("State file: {}", daemon_state_path().display());
            println!("Logs: {}", log_path.display());
            return Ok(());
        }

        return Err(anyhow!(
            "Daemon process {} did not stay running after startup",
            child_pid
        ));
    }

    let state = DaemonState {
        pid: std::process::id(),
        started_at: chrono::Utc::now(),
        operation_mode: config.operation_mode.clone(),
        config_path: config_path.display().to_string(),
    };
    let state_path = write_daemon_state(&state)?;

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
    if let Err(e) = orchestrator.start().await {
        clear_daemon_state().ok();
        return Err(e.into());
    }

    println!("{}", "Triage Warden started successfully".green());
    println!("Event bus listening for alerts...");
    println!("State file: {}", state_path.display());
    println!("Press Ctrl+C to stop");

    let signal = wait_for_shutdown_signal().await?;
    println!("\n{} ({})", "Shutting down...".yellow(), signal);

    let stop_result = orchestrator.stop().await;
    if let Err(e) = clear_daemon_state() {
        eprintln!("{}: {}", "Warning".yellow(), e);
    }
    stop_result.map_err(Into::into)
}

async fn cmd_stop() -> Result<()> {
    println!("{}", "Stopping Triage Warden...".yellow());

    let Some(state) = read_daemon_state()? else {
        println!("{}", "Triage Warden is not running".green());
        return Ok(());
    };

    if !process_is_running(state.pid) {
        println!(
            "{}: Found stale daemon state for pid {}, cleaning up.",
            "Info".yellow(),
            state.pid
        );
        clear_daemon_state()?;
        println!("{}", "Triage Warden is not running".green());
        return Ok(());
    }

    signal_process(state.pid, "-TERM")?;
    if !wait_for_process_exit(state.pid, std::time::Duration::from_secs(10)).await {
        println!(
            "{}: Daemon did not exit after SIGTERM, sending SIGKILL.",
            "Warning".yellow()
        );
        signal_process(state.pid, "-KILL")?;

        if !wait_for_process_exit(state.pid, std::time::Duration::from_secs(3)).await {
            return Err(anyhow!(
                "Failed to stop daemon process {} after SIGKILL",
                state.pid
            ));
        }
    }

    clear_daemon_state()?;
    println!("{}", "Triage Warden stopped".green());
    Ok(())
}

async fn cmd_status(format: OutputFormat) -> Result<()> {
    let state = read_daemon_state()?;
    let running = state
        .as_ref()
        .map(|s| process_is_running(s.pid))
        .unwrap_or(false);

    if state.is_some() && !running {
        clear_daemon_state().ok();
    }

    let pid = if running {
        state.as_ref().map(|s| s.pid)
    } else {
        None
    };
    let started_at = if running {
        state.as_ref().map(|s| s.started_at.to_rfc3339())
    } else {
        None
    };
    let uptime_seconds = if running {
        state
            .as_ref()
            .map(|s| (chrono::Utc::now() - s.started_at).num_seconds().max(0))
    } else {
        None
    };
    let operation_mode = if running {
        state.as_ref().map(|s| s.operation_mode.clone())
    } else {
        None
    };
    let active_config_path = if running {
        state.as_ref().map(|s| s.config_path.clone())
    } else {
        None
    };

    let status = serde_json::json!({
        "running": running,
        "version": env!("CARGO_PKG_VERSION"),
        "pid": pid,
        "started_at": started_at,
        "uptime_seconds": uptime_seconds,
        "operation_mode": operation_mode,
        "config_path": active_config_path,
        "state_file": daemon_state_path(),
        "log_file": daemon_log_path(),
        "incidents_in_progress": 0,
        "pending_approvals": 0,
    });

    if format == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&status)?);
    } else {
        println!("{}", "Triage Warden Status".bold());
        println!("─────────────────────");
        println!(
            "Running: {}",
            if running { "Yes".green() } else { "No".red() }
        );
        println!("Version: {}", env!("CARGO_PKG_VERSION"));
        if let Some(pid) = pid {
            println!("PID: {}", pid);
        }
        if let Some(uptime) = uptime_seconds {
            println!("Uptime: {}s", uptime);
        }
        if let Some(mode) = operation_mode {
            println!("Mode: {}", mode);
        }
        if let Some(config_path) = active_config_path {
            println!("Config: {}", config_path);
        }
        println!("State file: {}", daemon_state_path().display());
        println!("Logs: {}", daemon_log_path().display());
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
            let incident_id = match uuid::Uuid::parse_str(&id) {
                Ok(uuid) => uuid,
                Err(_) => {
                    println!("{}: Invalid UUID format", "Error".red());
                    return Ok(());
                }
            };

            let requested_status = status.to_ascii_lowercase();
            let result = match requested_status.as_str() {
                "dismissed" | "dismiss" => client.dismiss_incident(incident_id, None).await,
                "resolved" | "resolve" => client.resolve_incident(incident_id, None).await,
                "enriching" | "enrich" => client.enrich_incident(incident_id).await,
                _ => {
                    println!(
                        "{}: Unsupported status '{}' for CLI update",
                        "Error".red(),
                        status
                    );
                    println!("Supported values: dismissed, resolved, enriching");
                    return Ok(());
                }
            };

            match result {
                Ok(()) => {
                    if format == OutputFormat::Json {
                        let payload = serde_json::json!({
                            "incident_id": incident_id,
                            "status": requested_status,
                            "updated": true
                        });
                        println!("{}", serde_json::to_string_pretty(&payload)?);
                    } else {
                        println!(
                            "{} incident {} to {}",
                            "Updated".green(),
                            id.cyan(),
                            requested_status
                        );
                    }
                }
                Err(e) => {
                    println!("{}: {}", "Error".red(), e);
                    println!("Make sure the API server is running (triage-warden serve)");
                }
            }
        }
    }
    Ok(())
}

async fn cmd_connector(
    action: ConnectorCommands,
    config: AppConfig,
    format: OutputFormat,
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
                let (healthy, message) = test_connector_connectivity(connector).await;
                let status = if healthy {
                    "reachable".green().to_string()
                } else {
                    "unreachable".red().to_string()
                };

                if format == OutputFormat::Json {
                    let payload = serde_json::json!({
                        "name": name,
                        "type": connector.connector_type,
                        "base_url": connector.base_url,
                        "healthy": healthy,
                        "status": message
                    });
                    println!("{}", serde_json::to_string_pretty(&payload)?);
                } else {
                    println!("  Status: {}", status);
                    println!("  Details: {}", message);
                }
            } else {
                println!("{}", "Connector not found".red());
            }
        }
        ConnectorCommands::Health => {
            println!("{}", "Connector Health".bold());
            println!("────────────────");
            for (name, connector) in &config.connectors {
                if !connector.enabled {
                    println!("  {}: {}", name, "Disabled".red());
                    continue;
                }

                let (healthy, message) = test_connector_connectivity(connector).await;
                let health = if healthy {
                    "Reachable".green()
                } else {
                    "Unreachable".red()
                };
                println!("  {}: {} ({})", name, health, message);
            }
        }
    }
    Ok(())
}

async fn cmd_action(
    action: ActionCommands,
    _config: AppConfig,
    format: OutputFormat,
    api_url: &str,
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
        ActionCommands::Show { name } => match get_action_details(&name) {
            Some(details) => {
                if format == OutputFormat::Json {
                    let payload = serde_json::json!({
                        "name": details.name,
                        "description": details.description,
                        "required_params": details.required_params,
                        "optional_params": details.optional_params,
                        "supports_dry_run": details.supports_dry_run
                    });
                    println!("{}", serde_json::to_string_pretty(&payload)?);
                } else {
                    println!("Action: {}", details.name.cyan());
                    println!("─────────────────");
                    println!("Description: {}", details.description);
                    println!(
                        "Required params: {}",
                        if details.required_params.is_empty() {
                            "none".to_string()
                        } else {
                            details.required_params.join(", ")
                        }
                    );
                    println!(
                        "Optional params: {}",
                        if details.optional_params.is_empty() {
                            "none".to_string()
                        } else {
                            details.optional_params.join(", ")
                        }
                    );
                    println!(
                        "Supports dry-run: {}",
                        if details.supports_dry_run {
                            "yes"
                        } else {
                            "no"
                        }
                    );
                }
            }
            None => {
                println!("{}: Unknown action '{}'", "Error".red(), name);
                println!("Run `triage-warden action list` to see supported actions.");
            }
        },
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

            let (incident_id, request) = parse_action_execute_params(&name, &params)?;

            if dry_run {
                if format == OutputFormat::Json {
                    let payload = serde_json::json!({
                        "dry_run": true,
                        "incident_id": incident_id,
                        "request": request
                    });
                    println!("{}", serde_json::to_string_pretty(&payload)?);
                } else {
                    println!("{}: Would execute action '{}'", "Dry run".yellow(), name);
                    println!("Incident ID: {}", incident_id);
                    println!("Reason: {}", request.reason);
                    println!("Target: {}", serde_json::to_string_pretty(&request.target)?);
                    if let Some(parameters) = &request.parameters {
                        println!("Parameters: {}", serde_json::to_string_pretty(parameters)?);
                    }
                }
            } else {
                println!("Executing action: {}", name.cyan());
                let client = ApiClient::new(api_url)?;
                let response = client.execute_action(incident_id, &request).await?;

                if format == OutputFormat::Json {
                    println!("{}", serde_json::to_string_pretty(&response)?);
                } else {
                    println!("{}", "Action execution request accepted".green());
                    println!("Action ID: {}", response.action_id);
                    println!("Incident ID: {}", response.incident_id);
                    println!("Status: {}", response.status);
                    println!("Message: {}", response.message);
                }
            }
        }
    }
    Ok(())
}

async fn test_connector_connectivity(connector: &ConnectorConfig) -> (bool, String) {
    if connector.base_url.is_empty() {
        return (
            false,
            "No base URL configured for connectivity test".to_string(),
        );
    }

    let timeout_secs = connector.timeout_secs.clamp(1, 120);
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(timeout_secs))
        .build()
    {
        Ok(client) => client,
        Err(e) => return (false, format!("Failed to initialize HTTP client: {}", e)),
    };

    let response = client.get(&connector.base_url).send().await;
    match response {
        Ok(resp) => (
            true,
            format!(
                "HTTP {} from {}",
                resp.status().as_u16(),
                connector.base_url
            ),
        ),
        Err(e) => (false, e.to_string()),
    }
}

struct ActionDetails {
    name: &'static str,
    description: &'static str,
    required_params: &'static [&'static str],
    optional_params: &'static [&'static str],
    supports_dry_run: bool,
}

fn get_action_details(action_name: &str) -> Option<ActionDetails> {
    let normalized = action_name.to_ascii_lowercase();
    match normalized.as_str() {
        "isolate_host" => Some(ActionDetails {
            name: "isolate_host",
            description: "Isolate a host from the network to contain active threats.",
            required_params: &["hostname"],
            optional_params: &["ip", "reason", "incident_id"],
            supports_dry_run: true,
        }),
        "unisolate_host" => Some(ActionDetails {
            name: "unisolate_host",
            description: "Remove host isolation after remediation is complete.",
            required_params: &["hostname"],
            optional_params: &["ip", "reason", "incident_id"],
            supports_dry_run: true,
        }),
        "disable_user" => Some(ActionDetails {
            name: "disable_user",
            description: "Disable a user account in the identity provider.",
            required_params: &["username"],
            optional_params: &["email", "reason", "incident_id"],
            supports_dry_run: true,
        }),
        "create_ticket" => Some(ActionDetails {
            name: "create_ticket",
            description: "Create a ticket in the configured ticketing system.",
            required_params: &["title", "description"],
            optional_params: &["priority", "labels", "assignee"],
            supports_dry_run: true,
        }),
        "send_notification" => Some(ActionDetails {
            name: "send_notification",
            description: "Send notifications to configured channels.",
            required_params: &["template", "channel"],
            optional_params: &["severity", "incident_id", "context"],
            supports_dry_run: true,
        }),
        _ => None,
    }
}

fn parse_action_execute_params(
    action_name: &str,
    params: &str,
) -> Result<(uuid::Uuid, ExecuteActionRequest)> {
    let parsed: serde_json::Value = serde_json::from_str(params)
        .with_context(|| "Invalid --params JSON. Expected an object.".to_string())?;
    let mut params_obj = parsed
        .as_object()
        .cloned()
        .ok_or_else(|| anyhow!("Action parameters must be a JSON object"))?;

    let incident_id_raw = params_obj
        .remove("incident_id")
        .and_then(|v| v.as_str().map(ToOwned::to_owned))
        .ok_or_else(|| anyhow!("`incident_id` is required in --params as a UUID string"))?;
    let incident_id = uuid::Uuid::parse_str(&incident_id_raw)
        .with_context(|| format!("Invalid `incident_id` UUID: {}", incident_id_raw))?;

    let reason = params_obj
        .remove("reason")
        .and_then(|v| v.as_str().map(str::trim).map(ToOwned::to_owned))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("Action '{}' requested via triage-warden CLI", action_name));

    let skip_policy_check = params_obj
        .remove("skip_policy_check")
        .map(|v| {
            v.as_bool()
                .ok_or_else(|| anyhow!("`skip_policy_check` must be a boolean"))
        })
        .transpose()?
        .unwrap_or(false);

    let target = match params_obj.remove("target") {
        Some(target) => target,
        None => infer_action_target(action_name, &params_obj)?,
    };

    let mut request_parameters = match params_obj.remove("parameters") {
        Some(value) => value
            .as_object()
            .cloned()
            .ok_or_else(|| anyhow!("`parameters` must be a JSON object when provided"))?,
        None => serde_json::Map::new(),
    };

    for (key, value) in params_obj {
        request_parameters.entry(key).or_insert(value);
    }

    // Copy common fields from target into parameters for action handlers.
    enrich_parameters_from_target(&target, &mut request_parameters);
    request_parameters
        .entry("reason".to_string())
        .or_insert_with(|| serde_json::Value::String(reason.clone()));

    let parameters = if request_parameters.is_empty() {
        None
    } else {
        Some(serde_json::Value::Object(request_parameters))
    };

    Ok((
        incident_id,
        ExecuteActionRequest {
            action_type: action_name.to_string(),
            target,
            reason,
            parameters,
            skip_policy_check,
        },
    ))
}

fn infer_action_target(
    action_name: &str,
    params: &serde_json::Map<String, serde_json::Value>,
) -> Result<serde_json::Value> {
    let normalized = action_name.to_ascii_lowercase();
    let target = match normalized.as_str() {
        "isolate_host" | "unisolate_host" => serde_json::json!({
            "type": "host",
            "hostname": required_string_param(params, "hostname", action_name)?,
            "ip": optional_string_param(params, "ip")
        }),
        "disable_user" | "enable_user" | "reset_password" | "revoke_sessions" => {
            let username = optional_string_param(params, "username")
                .or_else(|| optional_string_param(params, "email"))
                .ok_or_else(|| {
                    anyhow!(
                        "`username` (or `email`) is required in --params for action `{}` when no explicit `target` is supplied",
                        action_name
                    )
                })?;
            serde_json::json!({
                "type": "user",
                "username": username,
                "email": optional_string_param(params, "email")
            })
        }
        "block_ip" | "unblock_ip" => serde_json::json!({
            "type": "ip_address",
            "ip": required_string_param(params, "ip", action_name)?
        }),
        "block_domain" => serde_json::json!({
            "type": "domain",
            "domain": required_string_param(params, "domain", action_name)?
        }),
        "quarantine_email" | "delete_email" => serde_json::json!({
            "type": "email",
            "message_id": required_string_param(params, "message_id", action_name)?
        }),
        "update_ticket" | "add_ticket_comment" => serde_json::json!({
            "type": "ticket",
            "ticket_id": required_string_param(params, "ticket_id", action_name)?
        }),
        _ => serde_json::json!({ "type": "none" }),
    };

    Ok(target)
}

fn required_string_param(
    params: &serde_json::Map<String, serde_json::Value>,
    key: &str,
    action_name: &str,
) -> Result<String> {
    optional_string_param(params, key).ok_or_else(|| {
        anyhow!(
            "`{}` is required in --params for action `{}` when no explicit `target` is supplied",
            key,
            action_name
        )
    })
}

fn optional_string_param(
    params: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Option<String> {
    params
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
}

fn enrich_parameters_from_target(
    target: &serde_json::Value,
    parameters: &mut serde_json::Map<String, serde_json::Value>,
) {
    let Some(target_obj) = target.as_object() else {
        return;
    };

    match target_obj
        .get("type")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
    {
        "host" => {
            copy_target_field(target_obj, "hostname", "hostname", parameters);
            copy_target_field(target_obj, "ip", "ip", parameters);
        }
        "user" => {
            copy_target_field(target_obj, "username", "username", parameters);
            copy_target_field(target_obj, "email", "email", parameters);
        }
        "ip_address" => copy_target_field(target_obj, "ip", "ip", parameters),
        "domain" => copy_target_field(target_obj, "domain", "domain", parameters),
        "email" => copy_target_field(target_obj, "message_id", "message_id", parameters),
        "ticket" => copy_target_field(target_obj, "ticket_id", "ticket_id", parameters),
        _ => {}
    }
}

fn copy_target_field(
    target_obj: &serde_json::Map<String, serde_json::Value>,
    source_key: &str,
    parameter_key: &str,
    parameters: &mut serde_json::Map<String, serde_json::Value>,
) {
    if let Some(value) = target_obj.get(source_key) {
        if !value.is_null() {
            parameters
                .entry(parameter_key.to_string())
                .or_insert_with(|| value.clone());
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_action_params_inferrs_host_target_and_parameters() {
        let params = serde_json::json!({
            "incident_id": "00000000-0000-0000-0000-000000000001",
            "hostname": "workstation-001",
            "reason": "Contain active malware",
            "ip": "10.0.0.8"
        })
        .to_string();

        let (incident_id, request) = parse_action_execute_params("isolate_host", &params).unwrap();
        assert_eq!(
            incident_id,
            uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap()
        );
        assert_eq!(request.action_type, "isolate_host");
        assert_eq!(request.target["type"], "host");
        assert_eq!(request.target["hostname"], "workstation-001");
        assert_eq!(request.target["ip"], "10.0.0.8");

        let request_params = request.parameters.as_ref().unwrap();
        assert_eq!(request_params["hostname"], "workstation-001");
        assert_eq!(request_params["ip"], "10.0.0.8");
        assert_eq!(request_params["reason"], "Contain active malware");
    }

    #[test]
    fn parse_action_params_merges_explicit_parameters() {
        let params = serde_json::json!({
            "incident_id": "00000000-0000-0000-0000-000000000002",
            "target": {
                "type": "user",
                "username": "alice",
                "email": "alice@example.com"
            },
            "parameters": {
                "revoke_sessions": false
            }
        })
        .to_string();

        let (_, request) = parse_action_execute_params("disable_user", &params).unwrap();
        let request_params = request.parameters.as_ref().unwrap();
        assert_eq!(request.target["type"], "user");
        assert_eq!(request_params["username"], "alice");
        assert_eq!(request_params["email"], "alice@example.com");
        assert_eq!(request_params["revoke_sessions"], false);
        assert_eq!(
            request.reason,
            "Action 'disable_user' requested via triage-warden CLI"
        );
    }

    #[test]
    fn parse_action_params_rejects_invalid_incident_id() {
        let params = serde_json::json!({
            "incident_id": "not-a-uuid",
            "hostname": "workstation-001"
        })
        .to_string();

        let err = parse_action_execute_params("isolate_host", &params).unwrap_err();
        assert!(err
            .to_string()
            .contains("Invalid `incident_id` UUID: not-a-uuid"));
    }

    #[test]
    fn parse_action_params_rejects_missing_incident_id() {
        let params = serde_json::json!({
            "hostname": "workstation-001"
        })
        .to_string();

        let err = parse_action_execute_params("isolate_host", &params).unwrap_err();
        assert!(err.to_string().contains("incident_id"));
    }

    #[test]
    fn parse_action_params_rejects_non_object() {
        let params = r#""just a string""#.to_string();
        let err = parse_action_execute_params("isolate_host", &params).unwrap_err();
        assert!(err.to_string().contains("JSON object"));
    }

    #[test]
    fn parse_action_params_rejects_invalid_json() {
        let params = "not json at all".to_string();
        let err = parse_action_execute_params("isolate_host", &params).unwrap_err();
        assert!(err.to_string().contains("Invalid --params JSON"));
    }

    #[test]
    fn parse_action_params_default_reason() {
        let params = serde_json::json!({
            "incident_id": "00000000-0000-0000-0000-000000000001",
            "hostname": "web-01"
        })
        .to_string();

        let (_, request) = parse_action_execute_params("isolate_host", &params).unwrap();
        assert!(request.reason.contains("triage-warden CLI"));
        assert!(request.reason.contains("isolate_host"));
    }

    #[test]
    fn parse_action_params_blank_reason_uses_default() {
        let params = serde_json::json!({
            "incident_id": "00000000-0000-0000-0000-000000000001",
            "hostname": "web-01",
            "reason": "   "
        })
        .to_string();

        let (_, request) = parse_action_execute_params("isolate_host", &params).unwrap();
        assert!(request.reason.contains("triage-warden CLI"));
    }

    #[test]
    fn parse_action_params_skip_policy_check() {
        let params = serde_json::json!({
            "incident_id": "00000000-0000-0000-0000-000000000001",
            "hostname": "web-01",
            "skip_policy_check": true
        })
        .to_string();

        let (_, request) = parse_action_execute_params("isolate_host", &params).unwrap();
        assert!(request.skip_policy_check);
    }

    #[test]
    fn parse_action_params_infer_user_target() {
        let params = serde_json::json!({
            "incident_id": "00000000-0000-0000-0000-000000000001",
            "username": "compromised_user",
            "email": "compromised@company.com"
        })
        .to_string();

        let (_, request) = parse_action_execute_params("disable_user", &params).unwrap();
        assert_eq!(request.target["type"], "user");
        assert_eq!(request.target["username"], "compromised_user");
        assert_eq!(request.target["email"], "compromised@company.com");
    }

    #[test]
    fn parse_action_params_infer_ip_target() {
        let params = serde_json::json!({
            "incident_id": "00000000-0000-0000-0000-000000000001",
            "ip": "10.0.0.50"
        })
        .to_string();

        let (_, request) = parse_action_execute_params("block_ip", &params).unwrap();
        assert_eq!(request.target["type"], "ip_address");
        assert_eq!(request.target["ip"], "10.0.0.50");
    }

    #[test]
    fn parse_action_params_infer_domain_target() {
        let params = serde_json::json!({
            "incident_id": "00000000-0000-0000-0000-000000000001",
            "domain": "evil.com"
        })
        .to_string();

        let (_, request) = parse_action_execute_params("block_domain", &params).unwrap();
        assert_eq!(request.target["type"], "domain");
        assert_eq!(request.target["domain"], "evil.com");
    }

    #[test]
    fn parse_action_params_unknown_action_gets_none_target() {
        let params = serde_json::json!({
            "incident_id": "00000000-0000-0000-0000-000000000001"
        })
        .to_string();

        let (_, request) = parse_action_execute_params("some_unknown_action", &params).unwrap();
        assert_eq!(request.target["type"], "none");
    }

    #[test]
    fn test_get_action_details_known_actions() {
        assert!(get_action_details("isolate_host").is_some());
        assert!(get_action_details("unisolate_host").is_some());
        assert!(get_action_details("disable_user").is_some());
        assert!(get_action_details("create_ticket").is_some());
        assert!(get_action_details("send_notification").is_some());
    }

    #[test]
    fn test_get_action_details_unknown_action() {
        assert!(get_action_details("nonexistent_action").is_none());
    }

    #[test]
    fn test_get_action_details_case_insensitive() {
        assert!(get_action_details("ISOLATE_HOST").is_some());
        assert!(get_action_details("Disable_User").is_some());
    }

    #[test]
    fn test_get_action_details_isolate_host_fields() {
        let details = get_action_details("isolate_host").unwrap();
        assert_eq!(details.name, "isolate_host");
        assert!(details.required_params.contains(&"hostname"));
        assert!(details.optional_params.contains(&"ip"));
        assert!(details.supports_dry_run);
    }

    #[test]
    fn test_output_format_from_str() {
        assert!("text".parse::<OutputFormat>().unwrap() == OutputFormat::Text);
        assert!("json".parse::<OutputFormat>().unwrap() == OutputFormat::Json);
        assert!("TEXT".parse::<OutputFormat>().unwrap() == OutputFormat::Text);
        assert!("JSON".parse::<OutputFormat>().unwrap() == OutputFormat::Json);
    }

    #[test]
    fn test_output_format_from_str_invalid() {
        assert!("xml".parse::<OutputFormat>().is_err());
        assert!("".parse::<OutputFormat>().is_err());
    }

    #[test]
    fn test_daemon_state_serialization_roundtrip() {
        let state = DaemonState {
            pid: 12345,
            started_at: chrono::Utc::now(),
            operation_mode: "supervised".to_string(),
            config_path: "/etc/tw/config.yaml".to_string(),
        };

        let serialized = serde_json::to_string(&state).unwrap();
        let deserialized: DaemonState = serde_json::from_str(&serialized).unwrap();

        assert_eq!(deserialized.pid, 12345);
        assert_eq!(deserialized.operation_mode, "supervised");
        assert_eq!(deserialized.config_path, "/etc/tw/config.yaml");
    }

    #[test]
    fn test_daemon_runtime_dir_env_override() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_str().unwrap().to_string();
        std::env::set_var(DAEMON_RUNTIME_DIR_ENV, &path);
        let result = daemon_runtime_dir();
        std::env::remove_var(DAEMON_RUNTIME_DIR_ENV);
        assert_eq!(result, std::path::PathBuf::from(&path));
    }

    #[test]
    fn test_daemon_runtime_dir_env_empty_fallback() {
        std::env::set_var(DAEMON_RUNTIME_DIR_ENV, "   ");
        let result = daemon_runtime_dir();
        std::env::remove_var(DAEMON_RUNTIME_DIR_ENV);
        // Should fall back to directories or .triage-warden/runtime, not the empty string
        assert_ne!(result, std::path::PathBuf::from("   "));
    }

    #[test]
    fn test_enrich_parameters_from_host_target() {
        let target = serde_json::json!({
            "type": "host",
            "hostname": "web-01",
            "ip": "10.0.0.5"
        });

        let mut params = serde_json::Map::new();
        enrich_parameters_from_target(&target, &mut params);

        assert_eq!(params["hostname"], "web-01");
        assert_eq!(params["ip"], "10.0.0.5");
    }

    #[test]
    fn test_enrich_parameters_from_user_target() {
        let target = serde_json::json!({
            "type": "user",
            "username": "alice",
            "email": "alice@company.com"
        });

        let mut params = serde_json::Map::new();
        enrich_parameters_from_target(&target, &mut params);

        assert_eq!(params["username"], "alice");
        assert_eq!(params["email"], "alice@company.com");
    }

    #[test]
    fn test_enrich_parameters_does_not_overwrite_existing() {
        let target = serde_json::json!({
            "type": "host",
            "hostname": "from-target"
        });

        let mut params = serde_json::Map::new();
        params.insert("hostname".to_string(), serde_json::json!("from-params"));
        enrich_parameters_from_target(&target, &mut params);

        // Existing value should not be overwritten
        assert_eq!(params["hostname"], "from-params");
    }

    #[test]
    fn test_enrich_parameters_null_target_field_skipped() {
        let target = serde_json::json!({
            "type": "host",
            "hostname": "web-01",
            "ip": null
        });

        let mut params = serde_json::Map::new();
        enrich_parameters_from_target(&target, &mut params);

        assert_eq!(params["hostname"], "web-01");
        // Null ip should not be added
        assert!(!params.contains_key("ip"));
    }

    #[test]
    fn test_enrich_parameters_non_object_target_noop() {
        let target = serde_json::json!("not an object");
        let mut params = serde_json::Map::new();
        enrich_parameters_from_target(&target, &mut params);
        assert!(params.is_empty());
    }
}
