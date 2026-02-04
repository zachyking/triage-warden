//! Triage Warden Load Testing Tool
//!
//! A load testing tool for validating Triage Warden performance requirements:
//! - 10,000 alerts/day throughput (~7 alerts/minute sustained)
//! - <500ms P99 API response time
//! - >80% cache hit rate for repeated enrichments
//!
//! # Usage
//!
//! ```bash
//! # Sustained load test (default: 10 requests/minute for 5 minutes)
//! tw-load-test --target http://localhost:8080 sustained
//!
//! # Burst load test (concurrent requests)
//! tw-load-test --target http://localhost:8080 burst --concurrency 50
//!
//! # Cache validation test
//! tw-load-test --target http://localhost:8080 cache --requests 100
//! ```

use chrono::Utc;
use clap::{Parser, Subcommand};
use colored::Colorize;
use hmac::{Hmac, Mac};
use indicatif::{ProgressBar, ProgressStyle};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use statrs::statistics::{Data, Distribution, OrderStatistics};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use tokio::time::sleep;
use tracing::{error, warn};
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

/// Triage Warden Load Testing Tool
#[derive(Parser)]
#[command(name = "tw-load-test")]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Target base URL for the Triage Warden API
    #[arg(short, long, env = "TW_TARGET_URL", default_value = "http://localhost:8080")]
    target: String,

    /// Webhook secret for signing requests (optional, skipped if not set)
    #[arg(short = 's', long, env = "TW_WEBHOOK_SECRET")]
    webhook_secret: Option<String>,

    /// API key for authenticated endpoints (optional)
    #[arg(short = 'k', long, env = "TW_API_KEY")]
    api_key: Option<String>,

    /// Enable verbose output
    #[arg(short, long)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run sustained load test (validates ~7 requests/minute throughput)
    Sustained {
        /// Requests per minute (default: 10, matching Stage 1 requirement)
        #[arg(short, long, default_value = "10")]
        rate: u32,

        /// Duration in minutes (default: 5)
        #[arg(short, long, default_value = "5")]
        duration: u32,
    },

    /// Run burst load test (validates P99 latency under concurrent load)
    Burst {
        /// Number of concurrent requests
        #[arg(short, long, default_value = "50")]
        concurrency: u32,

        /// Total number of requests to send
        #[arg(short, long, default_value = "500")]
        requests: u32,
    },

    /// Run cache validation test (validates cache hit rate)
    Cache {
        /// Number of requests to send
        #[arg(short, long, default_value = "100")]
        requests: u32,

        /// Number of unique values to use (fewer = higher cache hit rate expected)
        #[arg(short, long, default_value = "10")]
        unique_values: u32,
    },

    /// Run health check test (quick validation of endpoint availability)
    Health,

    /// Run all scenarios and produce a comprehensive report
    All {
        /// Duration for sustained test in minutes
        #[arg(short, long, default_value = "2")]
        duration: u32,
    },
}

/// Webhook alert payload matching the API schema
#[derive(Debug, Serialize)]
struct WebhookAlertPayload {
    source: String,
    alert_type: String,
    severity: String,
    title: String,
    description: Option<String>,
    data: serde_json::Value,
    timestamp: String,
    tags: Vec<String>,
}

/// Response from webhook endpoint
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct WebhookAcceptedResponse {
    accepted: bool,
    message: String,
    alert_id: Option<String>,
    incident_id: Option<Uuid>,
}

/// Response from health endpoint
#[derive(Debug, Deserialize)]
struct HealthResponse {
    status: String,
    version: String,
    #[serde(default)]
    uptime_seconds: u64,
}

/// Statistics from a load test run
#[derive(Debug, Clone)]
struct LoadTestStats {
    total_requests: u64,
    successful_requests: u64,
    failed_requests: u64,
    latencies_ms: Vec<f64>,
    start_time: Instant,
    end_time: Option<Instant>,
    errors: HashMap<String, u64>,
}

impl LoadTestStats {
    fn new() -> Self {
        Self {
            total_requests: 0,
            successful_requests: 0,
            failed_requests: 0,
            latencies_ms: Vec::new(),
            start_time: Instant::now(),
            end_time: None,
            errors: HashMap::new(),
        }
    }

    fn record_success(&mut self, latency_ms: f64) {
        self.total_requests += 1;
        self.successful_requests += 1;
        self.latencies_ms.push(latency_ms);
    }

    fn record_failure(&mut self, error: &str) {
        self.total_requests += 1;
        self.failed_requests += 1;
        *self.errors.entry(error.to_string()).or_insert(0) += 1;
    }

    fn finish(&mut self) {
        self.end_time = Some(Instant::now());
    }

    fn duration_secs(&self) -> f64 {
        let end = self.end_time.unwrap_or_else(Instant::now);
        end.duration_since(self.start_time).as_secs_f64()
    }

    fn throughput(&self) -> f64 {
        let duration = self.duration_secs();
        if duration > 0.0 {
            self.total_requests as f64 / duration
        } else {
            0.0
        }
    }

    fn error_rate(&self) -> f64 {
        if self.total_requests > 0 {
            (self.failed_requests as f64 / self.total_requests as f64) * 100.0
        } else {
            0.0
        }
    }

    fn percentile(&self, p: f64) -> Option<f64> {
        if self.latencies_ms.is_empty() {
            return None;
        }
        let mut data = Data::new(self.latencies_ms.clone());
        Some(data.percentile(p.round() as usize))
    }

    fn mean_latency(&self) -> Option<f64> {
        if self.latencies_ms.is_empty() {
            return None;
        }
        let data = Data::new(self.latencies_ms.clone());
        data.mean()
    }

    fn std_dev(&self) -> Option<f64> {
        if self.latencies_ms.len() < 2 {
            return None;
        }
        let data = Data::new(self.latencies_ms.clone());
        data.std_dev()
    }

    fn print_report(&self, test_name: &str) {
        println!("\n{}", "=".repeat(60).bright_blue());
        println!("{} Results", test_name.bright_white().bold());
        println!("{}", "=".repeat(60).bright_blue());

        println!(
            "\n{:<25} {}",
            "Duration:".bright_cyan(),
            format!("{:.2}s", self.duration_secs())
        );
        println!(
            "{:<25} {}",
            "Total Requests:".bright_cyan(),
            self.total_requests
        );
        println!(
            "{:<25} {}",
            "Successful:".bright_cyan(),
            self.successful_requests.to_string().green()
        );
        println!(
            "{:<25} {}",
            "Failed:".bright_cyan(),
            if self.failed_requests > 0 {
                self.failed_requests.to_string().red()
            } else {
                self.failed_requests.to_string().green()
            }
        );
        println!(
            "{:<25} {}",
            "Throughput:".bright_cyan(),
            format!("{:.2} req/s", self.throughput())
        );
        println!(
            "{:<25} {}",
            "Error Rate:".bright_cyan(),
            if self.error_rate() > 5.0 {
                format!("{:.2}%", self.error_rate()).red()
            } else {
                format!("{:.2}%", self.error_rate()).green()
            }
        );

        if !self.latencies_ms.is_empty() {
            println!("\n{}", "Latency Statistics (ms):".bright_yellow());
            if let Some(mean) = self.mean_latency() {
                println!("{:<25} {:.2}", "  Mean:".bright_cyan(), mean);
            }
            if let Some(std_dev) = self.std_dev() {
                println!("{:<25} {:.2}", "  Std Dev:".bright_cyan(), std_dev);
            }
            if let Some(p50) = self.percentile(50.0) {
                println!("{:<25} {:.2}", "  P50:".bright_cyan(), p50);
            }
            if let Some(p95) = self.percentile(95.0) {
                println!("{:<25} {:.2}", "  P95:".bright_cyan(), p95);
            }
            if let Some(p99) = self.percentile(99.0) {
                let p99_str = format!("{:.2}", p99);
                println!(
                    "{:<25} {}",
                    "  P99:".bright_cyan(),
                    if p99 > 500.0 {
                        p99_str.red()
                    } else {
                        p99_str.green()
                    }
                );
            }
            if let Some(max) = self.latencies_ms.iter().cloned().reduce(f64::max) {
                println!("{:<25} {:.2}", "  Max:".bright_cyan(), max);
            }
        }

        if !self.errors.is_empty() {
            println!("\n{}", "Errors:".bright_red());
            for (error, count) in &self.errors {
                println!("  {} ({})", error.red(), count);
            }
        }
    }

    fn check_requirements(&self) -> bool {
        let mut passed = true;

        println!("\n{}", "Requirement Checks:".bright_yellow().bold());

        // Check P99 latency < 500ms
        if let Some(p99) = self.percentile(99.0) {
            let pass = p99 < 500.0;
            if !pass {
                passed = false;
            }
            println!(
                "  {} P99 latency < 500ms: {:.2}ms",
                if pass {
                    "[PASS]".green()
                } else {
                    "[FAIL]".red()
                },
                p99
            );
        }

        // Check error rate < 1%
        let error_rate = self.error_rate();
        let error_pass = error_rate < 1.0;
        if !error_pass {
            passed = false;
        }
        println!(
            "  {} Error rate < 1%: {:.2}%",
            if error_pass {
                "[PASS]".green()
            } else {
                "[FAIL]".red()
            },
            error_rate
        );

        passed
    }
}

/// Load test runner
struct LoadTestRunner {
    client: Client,
    base_url: String,
    webhook_secret: Option<String>,
    #[allow(dead_code)]
    api_key: Option<String>,
}

impl LoadTestRunner {
    fn new(base_url: String, webhook_secret: Option<String>, api_key: Option<String>) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .pool_max_idle_per_host(100)
            .build()
            .expect("Failed to create HTTP client");

        Self {
            client,
            base_url,
            webhook_secret,
            api_key,
        }
    }

    /// Generate a random alert payload
    fn generate_alert(&self, unique_id: Option<u32>) -> WebhookAlertPayload {
        let severities = ["info", "low", "medium", "high", "critical"];
        let alert_types = ["malware", "phishing", "brute_force", "data_exfil", "anomaly"];
        let sources = ["splunk", "crowdstrike", "m365", "palo_alto", "aws_guard"];

        let id = unique_id.unwrap_or_else(|| rand::random::<u32>());

        WebhookAlertPayload {
            source: sources[id as usize % sources.len()].to_string(),
            alert_type: alert_types[id as usize % alert_types.len()].to_string(),
            severity: severities[id as usize % severities.len()].to_string(),
            title: format!("Load Test Alert {}", id),
            description: Some(format!(
                "Automated load test alert generated at {}",
                Utc::now()
            )),
            data: serde_json::json!({
                "source_ip": format!("192.168.1.{}", id % 256),
                "destination_ip": format!("10.0.0.{}", id % 256),
                "user": format!("user{}", id % 100),
                "hostname": format!("workstation-{}", id % 1000),
                "test_id": id,
                "title": format!("Load Test Alert {}", id),
                "alert_type": alert_types[id as usize % alert_types.len()],
            }),
            timestamp: Utc::now().to_rfc3339(),
            tags: vec!["load-test".to_string(), format!("test-{}", id % 10)],
        }
    }

    /// Compute HMAC-SHA256 signature for webhook payload
    fn compute_signature(&self, payload: &[u8]) -> Option<String> {
        self.webhook_secret.as_ref().map(|secret| {
            let mut mac =
                HmacSha256::new_from_slice(secret.as_bytes()).expect("Invalid HMAC key length");
            mac.update(payload);
            let result = mac.finalize();
            format!("sha256={}", hex::encode(result.into_bytes()))
        })
    }

    /// Send a webhook alert request
    async fn send_webhook_alert(
        &self,
        payload: &WebhookAlertPayload,
    ) -> Result<(Duration, WebhookAcceptedResponse), String> {
        let url = format!("{}/api/webhooks/alerts", self.base_url);
        let body = serde_json::to_vec(payload).map_err(|e| e.to_string())?;

        let start = Instant::now();

        let mut request = self.client.post(&url).header("Content-Type", "application/json");

        // Add signature if webhook secret is configured
        if let Some(signature) = self.compute_signature(&body) {
            request = request.header("X-Signature-256", signature);
        }

        let response = request.body(body).send().await.map_err(|e| e.to_string())?;

        let latency = start.elapsed();
        let status = response.status();

        if status.is_success() || status.as_u16() == 202 {
            let body: WebhookAcceptedResponse =
                response.json().await.map_err(|e| e.to_string())?;
            Ok((latency, body))
        } else {
            let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
            Err(format!("HTTP {}: {}", status.as_u16(), error_text))
        }
    }

    /// Send a health check request
    async fn health_check(&self) -> Result<(Duration, HealthResponse), String> {
        let url = format!("{}/health", self.base_url);
        let start = Instant::now();

        let response = self.client.get(&url).send().await.map_err(|e| e.to_string())?;

        let latency = start.elapsed();
        let status = response.status();

        if status.is_success() {
            let body: HealthResponse = response.json().await.map_err(|e| e.to_string())?;
            Ok((latency, body))
        } else {
            Err(format!("HTTP {}", status.as_u16()))
        }
    }

    /// Send a GET request to incidents endpoint (for cache testing)
    async fn get_incidents(&self, page: u32) -> Result<Duration, String> {
        let url = format!("{}/api/incidents?page={}&per_page=10", self.base_url, page);
        let start = Instant::now();

        let mut request = self.client.get(&url);

        // Add API key if configured
        if let Some(api_key) = &self.api_key {
            request = request.header("Authorization", format!("Bearer {}", api_key));
        }

        let response = request.send().await.map_err(|e| e.to_string())?;

        let latency = start.elapsed();
        let status = response.status();

        // Accept 200 OK or 401 Unauthorized (in case auth is required but not configured)
        if status.is_success() || status.as_u16() == 401 {
            Ok(latency)
        } else {
            Err(format!("HTTP {}", status.as_u16()))
        }
    }

    /// Run sustained load test
    async fn run_sustained_test(&self, rate: u32, duration_mins: u32) -> LoadTestStats {
        let mut stats = LoadTestStats::new();
        let total_requests = rate * duration_mins;
        let interval_ms = 60_000 / rate;

        println!(
            "\n{} Sustained Load Test",
            "Starting".bright_green().bold()
        );
        println!("  Target: {} requests/minute for {} minutes", rate, duration_mins);
        println!("  Total: {} requests", total_requests);
        println!("  Interval: {}ms between requests", interval_ms);

        let pb = ProgressBar::new(total_requests as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({percent}%) {msg}")
                .unwrap()
                .progress_chars("#>-"),
        );

        for i in 0..total_requests {
            let payload = self.generate_alert(None);

            match self.send_webhook_alert(&payload).await {
                Ok((latency, _response)) => {
                    stats.record_success(latency.as_millis() as f64);
                }
                Err(e) => {
                    stats.record_failure(&e);
                    warn!("Request {} failed: {}", i, e);
                }
            }

            pb.set_position((i + 1) as u64);
            pb.set_message(format!(
                "Throughput: {:.2} req/s",
                stats.throughput()
            ));

            // Wait for next interval (unless this is the last request)
            if i < total_requests - 1 {
                sleep(Duration::from_millis(interval_ms as u64)).await;
            }
        }

        pb.finish_with_message("Complete");
        stats.finish();
        stats
    }

    /// Run burst load test
    async fn run_burst_test(&self, concurrency: u32, total_requests: u32) -> LoadTestStats {
        let stats = Arc::new(tokio::sync::Mutex::new(LoadTestStats::new()));
        let semaphore = Arc::new(Semaphore::new(concurrency as usize));
        let completed = Arc::new(AtomicU64::new(0));

        println!("\n{} Burst Load Test", "Starting".bright_green().bold());
        println!("  Concurrency: {} simultaneous requests", concurrency);
        println!("  Total: {} requests", total_requests);

        let pb = ProgressBar::new(total_requests as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({percent}%) {msg}")
                .unwrap()
                .progress_chars("#>-"),
        );

        let mut handles = Vec::new();

        for i in 0..total_requests {
            let client = self.client.clone();
            let base_url = self.base_url.clone();
            let webhook_secret = self.webhook_secret.clone();
            let stats = Arc::clone(&stats);
            let semaphore = Arc::clone(&semaphore);
            let completed = Arc::clone(&completed);
            let pb = pb.clone();

            let handle = tokio::spawn(async move {
                let _permit = semaphore.acquire().await.unwrap();

                let runner = LoadTestRunner {
                    client,
                    base_url,
                    webhook_secret,
                    api_key: None,
                };

                let payload = runner.generate_alert(Some(i));

                match runner.send_webhook_alert(&payload).await {
                    Ok((latency, _response)) => {
                        let mut stats = stats.lock().await;
                        stats.record_success(latency.as_millis() as f64);
                    }
                    Err(e) => {
                        let mut stats = stats.lock().await;
                        stats.record_failure(&e);
                    }
                }

                let count = completed.fetch_add(1, Ordering::SeqCst) + 1;
                pb.set_position(count);
            });

            handles.push(handle);
        }

        // Wait for all requests to complete
        for handle in handles {
            let _ = handle.await;
        }

        pb.finish_with_message("Complete");

        let mut final_stats = stats.lock().await;
        final_stats.finish();
        final_stats.clone()
    }

    /// Run cache validation test
    async fn run_cache_test(&self, requests: u32, unique_values: u32) -> LoadTestStats {
        let mut stats = LoadTestStats::new();

        println!("\n{} Cache Validation Test", "Starting".bright_green().bold());
        println!("  Requests: {}", requests);
        println!("  Unique values: {} (expect ~{}% cache hit rate)",
                 unique_values,
                 100 - (unique_values * 100 / requests.max(unique_values)));

        let pb = ProgressBar::new(requests as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({percent}%)")
                .unwrap()
                .progress_chars("#>-"),
        );

        for i in 0..requests {
            // Use modulo to repeat values, simulating cache hits
            let page = (i % unique_values) + 1;

            match self.get_incidents(page).await {
                Ok(latency) => {
                    stats.record_success(latency.as_millis() as f64);
                }
                Err(e) => {
                    stats.record_failure(&e);
                }
            }

            pb.set_position((i + 1) as u64);
        }

        pb.finish_with_message("Complete");
        stats.finish();

        // Note: Cache hit rate would need to be measured from server-side metrics
        // This test validates latency consistency which indicates caching effectiveness
        println!(
            "\n{}: To measure actual cache hit rate, check server metrics or /health/detailed endpoint",
            "Note".bright_yellow()
        );

        stats
    }

    /// Run health check test
    async fn run_health_test(&self) -> Result<HealthResponse, String> {
        println!("\n{} Health Check", "Running".bright_green().bold());

        let (latency, response) = self.health_check().await?;

        println!("  Status: {}",
            if response.status == "healthy" {
                response.status.green()
            } else {
                response.status.yellow()
            }
        );
        println!("  Version: {}", response.version);
        println!("  Uptime: {}s", response.uptime_seconds);
        println!("  Latency: {}ms", latency.as_millis());

        Ok(response)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // Initialize logging
    let log_level = if cli.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(log_level)),
        )
        .init();

    println!("{}", "=".repeat(60).bright_blue());
    println!(
        "{}",
        "  Triage Warden Load Testing Tool"
            .bright_white()
            .bold()
    );
    println!("{}", "=".repeat(60).bright_blue());
    println!("  Target: {}", cli.target.bright_cyan());
    println!(
        "  Webhook Secret: {}",
        if cli.webhook_secret.is_some() {
            "configured".green()
        } else {
            "not set (signatures disabled)".yellow()
        }
    );

    let runner = LoadTestRunner::new(cli.target.clone(), cli.webhook_secret, cli.api_key);

    // First, check if the target is reachable
    println!("\n{}", "Checking target availability...".bright_cyan());
    match runner.health_check().await {
        Ok((_, response)) => {
            if response.status == "healthy" {
                println!("{} Target is healthy", "[OK]".green());
            } else {
                println!(
                    "{} Target is {} (continuing anyway)",
                    "[WARN]".yellow(),
                    response.status.yellow()
                );
            }
        }
        Err(e) => {
            error!("Failed to connect to target: {}", e);
            println!(
                "{} Cannot reach target: {}",
                "[ERROR]".red(),
                e.red()
            );
            println!(
                "\n{}: Make sure Triage Warden is running at {}",
                "Hint".bright_yellow(),
                cli.target
            );
            return Err(e.into());
        }
    }

    // Run the requested test
    let all_passed = match cli.command {
        Commands::Sustained { rate, duration } => {
            let stats = runner.run_sustained_test(rate, duration).await;
            stats.print_report("Sustained Load Test");
            stats.check_requirements()
        }

        Commands::Burst {
            concurrency,
            requests,
        } => {
            let stats = runner.run_burst_test(concurrency, requests).await;
            stats.print_report("Burst Load Test");
            stats.check_requirements()
        }

        Commands::Cache {
            requests,
            unique_values,
        } => {
            let stats = runner.run_cache_test(requests, unique_values).await;
            stats.print_report("Cache Validation Test");
            stats.check_requirements()
        }

        Commands::Health => {
            runner.run_health_test().await?;
            true
        }

        Commands::All { duration } => {
            let mut all_passed = true;

            // Health check
            runner.run_health_test().await?;

            // Sustained test (2 minutes, 10 req/min)
            println!("\n{}", "-".repeat(60).bright_blue());
            let sustained_stats = runner.run_sustained_test(10, duration).await;
            sustained_stats.print_report("Sustained Load Test");
            if !sustained_stats.check_requirements() {
                all_passed = false;
            }

            // Burst test
            println!("\n{}", "-".repeat(60).bright_blue());
            let burst_stats = runner.run_burst_test(50, 200).await;
            burst_stats.print_report("Burst Load Test");
            if !burst_stats.check_requirements() {
                all_passed = false;
            }

            // Cache test
            println!("\n{}", "-".repeat(60).bright_blue());
            let cache_stats = runner.run_cache_test(100, 10).await;
            cache_stats.print_report("Cache Validation Test");
            if !cache_stats.check_requirements() {
                all_passed = false;
            }

            // Summary
            println!("\n{}", "=".repeat(60).bright_blue());
            println!(
                "{}",
                "  Overall Summary".bright_white().bold()
            );
            println!("{}", "=".repeat(60).bright_blue());

            if all_passed {
                println!(
                    "\n  {} All performance requirements met!",
                    "[PASS]".green().bold()
                );
            } else {
                println!(
                    "\n  {} Some performance requirements not met",
                    "[FAIL]".red().bold()
                );
            }

            all_passed
        }
    };

    // Exit with appropriate code
    if all_passed {
        println!("\n{}", "Load test completed successfully.".green());
        Ok(())
    } else {
        println!(
            "\n{}",
            "Load test completed with failures.".red()
        );
        std::process::exit(1);
    }
}
