//! Run triage agent action.
//!
//! This action triggers the triage workflow for an incident and returns
//! a structured analysis derived from incident context.
//!
//! When a `triage_service_url` is configured (via `TW_TRIAGE_SERVICE_URL`),
//! the action delegates to the Python AI triage service. If the service is
//! unavailable or returns an error, the action falls back to the built-in
//! heuristic pipeline and logs a warning.

use crate::registry::{
    Action, ActionContext, ActionError, ActionResult, ParameterDef, ParameterType,
};
use async_trait::async_trait;
use chrono::Utc;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;
use std::time::Duration;
use tracing::{info, instrument, warn};

/// Result of triage analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageResult {
    /// The verdict from triage (true_positive, false_positive, suspicious, inconclusive).
    pub verdict: String,
    /// Confidence level (0.0 - 1.0).
    pub confidence: f64,
    /// Detailed analysis explanation.
    pub analysis: String,
    /// Recommended actions based on the analysis.
    pub recommended_actions: Vec<String>,
    /// Risk score (0-100).
    pub risk_score: u32,
    /// Indicators of compromise found.
    pub iocs: Vec<String>,
    /// MITRE ATT&CK techniques identified.
    pub mitre_techniques: Vec<String>,
}

/// Configuration for the triage agent.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct AgentConfig {
    /// Model identifier for traceability (heuristic pipeline still used by this action).
    pub model: Option<String>,
    /// Maximum tokens for response (validated but not consumed by heuristic pipeline).
    pub max_tokens: Option<u32>,
    /// Temperature for response generation (validated but not consumed by heuristic pipeline).
    pub temperature: Option<f64>,
    /// Whether to include IOC extraction.
    pub extract_iocs: bool,
    /// Whether to include MITRE ATT&CK mapping.
    pub map_mitre: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
struct IncidentContextInput {
    title: Option<String>,
    description: Option<String>,
    severity: Option<String>,
    sender: Option<String>,
    source_ip: Option<String>,
    urls: Vec<String>,
    attachments: Vec<String>,
    indicators: Vec<String>,
    authentication_failures: bool,
    tags: Vec<String>,
}

// ---------------------------------------------------------------------------
// Python triage service request/response types
// ---------------------------------------------------------------------------

/// Request body sent to the Python triage service.
#[derive(Debug, Serialize)]
struct TriageServiceRequest {
    alert_type: String,
    alert_data: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    context: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    priority: Option<String>,
}

/// Indicator in the triage service response.
#[derive(Debug, Deserialize)]
struct ServiceIndicator {
    #[serde(rename = "type")]
    indicator_type: String,
    value: String,
}

/// MITRE technique in the triage service response.
#[derive(Debug, Deserialize)]
struct ServiceMitreTechnique {
    id: String,
    name: String,
}

/// Recommended action in the triage service response.
#[derive(Debug, Deserialize)]
struct ServiceRecommendedAction {
    action: String,
}

/// Response body from the Python triage service.
#[derive(Debug, Deserialize)]
struct TriageServiceResponse {
    verdict: String,
    confidence: f64,
    severity: String,
    summary: String,
    #[serde(default)]
    reasoning: String,
    #[serde(default)]
    indicators: Vec<ServiceIndicator>,
    #[serde(default)]
    mitre_techniques: Vec<ServiceMitreTechnique>,
    #[serde(default)]
    recommended_actions: Vec<ServiceRecommendedAction>,
    #[serde(default)]
    analyzed_by: String,
    #[serde(default)]
    tokens_used: u32,
    #[serde(default)]
    execution_time_seconds: f64,
}

/// Action to trigger triage for an incident.
pub struct RunTriageAgentAction {
    /// Optional URL of the Python triage service.
    triage_service_url: Option<String>,
    /// HTTP client for calling the triage service (lazily shared).
    http_client: reqwest::Client,
}

impl RunTriageAgentAction {
    /// Creates a new run triage agent action.
    ///
    /// If no URL is provided, only the heuristic pipeline is used.
    pub fn new() -> Self {
        Self {
            triage_service_url: None,
            http_client: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap_or_default(),
        }
    }

    /// Creates a new action configured to call the Python triage service.
    pub fn with_triage_service_url(mut self, url: String) -> Self {
        self.triage_service_url = Some(url);
        self
    }

    /// Resolve triage service URL using override precedence:
    /// 1) action parameter `triage_service_url`
    /// 2) metadata key `triage_service_url` (backward-compatible)
    /// 3) action field configured via builder
    /// 4) process env `TW_TRIAGE_SERVICE_URL`
    fn resolve_service_url(&self, context: &ActionContext) -> Option<String> {
        context
            .get_string("triage_service_url")
            .or_else(|| {
                context
                    .metadata
                    .get("triage_service_url")
                    .and_then(|v| v.as_str().map(String::from))
            })
            .or_else(|| self.triage_service_url.clone())
            .or_else(|| std::env::var("TW_TRIAGE_SERVICE_URL").ok())
            .map(|u| u.trim().to_string())
            .filter(|u| !u.is_empty())
    }

    // ------------------------------------------------------------------
    // Python AI triage service integration
    // ------------------------------------------------------------------

    /// Call the Python triage service with 1 retry on timeout/5xx.
    async fn call_triage_service(
        &self,
        url: &str,
        incident_context: &IncidentContextInput,
    ) -> Result<TriageServiceResponse, String> {
        let alert_type = self.infer_alert_type(incident_context);
        let alert_data =
            serde_json::to_value(incident_context).unwrap_or_else(|_| serde_json::json!({}));

        let body = TriageServiceRequest {
            alert_type,
            alert_data,
            context: None,
            priority: incident_context.severity.clone(),
        };

        let endpoint = format!("{}/api/triage", url.trim_end_matches('/'));

        // Attempt with 1 retry on retriable errors
        for attempt in 0..2u8 {
            match self.http_client.post(&endpoint).json(&body).send().await {
                Ok(resp) => {
                    let status = resp.status();
                    if status.is_success() {
                        return resp.json::<TriageServiceResponse>().await.map_err(|e| {
                            format!("Failed to parse triage service response: {}", e)
                        });
                    }
                    // Retry on 5xx, fail immediately on 4xx
                    if status.is_server_error() && attempt == 0 {
                        warn!(
                            status = %status,
                            attempt = attempt + 1,
                            "Triage service returned server error, retrying"
                        );
                        tokio::time::sleep(Duration::from_millis(500)).await;
                        continue;
                    }
                    let detail = resp.text().await.unwrap_or_default();
                    return Err(format!("Triage service returned {}: {}", status, detail));
                }
                Err(e) => {
                    // Retry on timeout, fail on other transport errors
                    if e.is_timeout() && attempt == 0 {
                        warn!(
                            attempt = attempt + 1,
                            "Triage service request timed out, retrying"
                        );
                        continue;
                    }
                    return Err(format!("Triage service request failed: {}", e));
                }
            }
        }
        Err("Triage service exhausted all retries".to_string())
    }

    /// Convert service response to `TriageResult` and extracted metadata.
    ///
    /// Returns `(TriageResult, severity, tokens_used, execution_time_seconds)`.
    fn service_response_to_result(resp: TriageServiceResponse) -> (TriageResult, String, u32, f64) {
        let verdict = Self::normalize_verdict(&resp.verdict);
        let risk_score = (resp.confidence * 100.0).round() as u32;

        let result = TriageResult {
            verdict,
            confidence: resp.confidence,
            analysis: if resp.reasoning.is_empty() {
                resp.summary
            } else {
                format!("{}\n\n{}", resp.summary, resp.reasoning)
            },
            recommended_actions: resp
                .recommended_actions
                .into_iter()
                .map(|a| a.action)
                .collect(),
            risk_score: risk_score.clamp(0, 100),
            iocs: resp
                .indicators
                .into_iter()
                .map(|i| format!("{}:{}", i.indicator_type, i.value))
                .collect(),
            mitre_techniques: resp
                .mitre_techniques
                .into_iter()
                .map(|t| format!("{} - {}", t.id, t.name))
                .collect(),
        };

        (
            result,
            resp.severity,
            resp.tokens_used,
            resp.execution_time_seconds,
        )
    }

    /// Normalize verdicts from heterogeneous providers into one canonical taxonomy.
    fn normalize_verdict(verdict: &str) -> String {
        match verdict.trim().to_ascii_lowercase().as_str() {
            "true_positive" | "malicious" => "true_positive".to_string(),
            "false_positive" | "benign" | "clean" => "false_positive".to_string(),
            "suspicious" => "suspicious".to_string(),
            "inconclusive" => "inconclusive".to_string(),
            _ => "inconclusive".to_string(),
        }
    }

    /// Infer alert type from context fields.
    fn infer_alert_type(&self, ctx: &IncidentContextInput) -> String {
        let text = format!(
            "{} {} {}",
            ctx.title.as_deref().unwrap_or(""),
            ctx.description.as_deref().unwrap_or(""),
            ctx.tags.join(" ")
        )
        .to_ascii_lowercase();

        if text.contains("phishing") || ctx.sender.is_some() {
            "phishing".to_string()
        } else if text.contains("malware") || Self::risky_attachment_count(&ctx.attachments) > 0 {
            "malware".to_string()
        } else if text.contains("brute") || ctx.authentication_failures {
            "brute_force".to_string()
        } else {
            "generic".to_string()
        }
    }

    // ------------------------------------------------------------------
    // Heuristic pipeline (unchanged)
    // ------------------------------------------------------------------

    fn validate_agent_config(agent_config: &AgentConfig) -> Result<(), ActionError> {
        if let Some(max_tokens) = agent_config.max_tokens {
            if max_tokens == 0 {
                return Err(ActionError::InvalidParameters(
                    "agent_config.max_tokens must be greater than 0".to_string(),
                ));
            }
        }

        if let Some(temperature) = agent_config.temperature {
            if !(0.0..=2.0).contains(&temperature) {
                return Err(ActionError::InvalidParameters(
                    "agent_config.temperature must be between 0.0 and 2.0".to_string(),
                ));
            }
        }

        Ok(())
    }

    fn parse_incident_context(
        context: &ActionContext,
    ) -> Result<IncidentContextInput, ActionError> {
        let mut incident_context: IncidentContextInput = match context.get_param("incident_context")
        {
            Some(value) => serde_json::from_value(value.clone()).map_err(|err| {
                ActionError::InvalidParameters(format!("Invalid incident_context: {}", err))
            })?,
            None => IncidentContextInput::default(),
        };

        if incident_context.tags.is_empty() {
            if let Some(tags) = context
                .metadata
                .get("tags")
                .and_then(|value| value.as_array())
            {
                incident_context.tags = tags
                    .iter()
                    .filter_map(|tag| tag.as_str().map(str::to_string))
                    .collect();
            }
        }

        if incident_context.indicators.is_empty() {
            if let Some(indicators) = context
                .metadata
                .get("indicators")
                .and_then(|value| value.as_array())
            {
                incident_context.indicators = indicators
                    .iter()
                    .filter_map(|ioc| ioc.as_str().map(str::to_string))
                    .collect();
            }
        }

        Ok(incident_context)
    }

    fn contains_credential_theme(text: &str) -> bool {
        let normalized = text.to_ascii_lowercase();
        [
            "password",
            "verify",
            "authentication",
            "mfa",
            "credential",
            "login",
            "sign in",
            "invoice",
            "wire transfer",
            "urgent",
        ]
        .iter()
        .any(|token| normalized.contains(token))
    }

    fn risky_attachment_count(attachments: &[String]) -> usize {
        attachments
            .iter()
            .filter(|attachment| {
                let lower = attachment.to_ascii_lowercase();
                [
                    ".exe", ".dll", ".js", ".vbs", ".scr", ".iso", ".hta", ".lnk",
                ]
                .iter()
                .any(|extension| lower.ends_with(extension))
            })
            .count()
    }

    fn suspicious_url_count(urls: &[String]) -> usize {
        urls.iter()
            .filter(|url| {
                let lower = url.to_ascii_lowercase();
                lower.contains("@")
                    || lower.contains("bit.ly")
                    || lower.contains("tinyurl")
                    || lower.contains("ipfs")
                    || lower.contains("xn--")
                    || lower.ends_with(".zip")
                    || lower.ends_with(".top")
                    || lower.ends_with(".ru")
            })
            .count()
    }

    fn severity_risk(severity: Option<&str>) -> u32 {
        match severity.unwrap_or("unknown").to_ascii_lowercase().as_str() {
            "critical" => 35,
            "high" => 25,
            "medium" => 15,
            "low" => 5,
            _ => 10,
        }
    }

    fn calculate_risk_score(context: &IncidentContextInput) -> (u32, Vec<String>) {
        let mut score = Self::severity_risk(context.severity.as_deref());
        let mut evidence = Vec::new();

        if let Some(severity) = context.severity.as_deref() {
            evidence.push(format!("Severity classified as {}", severity));
        }

        if context.authentication_failures {
            score += 20;
            evidence.push("Authentication failures observed".to_string());
        }

        let suspicious_urls = Self::suspicious_url_count(&context.urls);
        if suspicious_urls > 0 {
            score += (suspicious_urls as u32 * 10).min(30);
            evidence.push(format!(
                "{} potentially suspicious URL(s) detected",
                suspicious_urls
            ));
        }

        let risky_attachments = Self::risky_attachment_count(&context.attachments);
        if risky_attachments > 0 {
            score += (risky_attachments as u32 * 12).min(36);
            evidence.push(format!(
                "{} potentially risky attachment(s) present",
                risky_attachments
            ));
        }

        let mut text_blob = String::new();
        if let Some(title) = context.title.as_deref() {
            text_blob.push_str(title);
            text_blob.push(' ');
        }
        if let Some(description) = context.description.as_deref() {
            text_blob.push_str(description);
        }

        if !text_blob.is_empty() && Self::contains_credential_theme(&text_blob) {
            score += 15;
            evidence.push("Content includes credential-theft style language".to_string());
        }

        if !context.indicators.is_empty() {
            score += (context.indicators.len() as u32 * 4).min(16);
            evidence.push(format!(
                "{} pre-extracted indicator(s) provided",
                context.indicators.len()
            ));
        }

        let high_risk_tags = context
            .tags
            .iter()
            .filter(|tag| {
                matches!(
                    tag.to_ascii_lowercase().as_str(),
                    "phishing" | "credential_theft" | "malware" | "ransomware" | "spoofing"
                )
            })
            .count();

        if high_risk_tags > 0 {
            score += (high_risk_tags as u32 * 8).min(16);
            evidence.push(format!(
                "{} high-risk semantic tag(s) attached",
                high_risk_tags
            ));
        }

        if evidence.is_empty() {
            evidence.push("No strong malicious indicators detected".to_string());
        }

        (score.clamp(0, 100), evidence)
    }

    fn classify_verdict(score: u32) -> &'static str {
        if score >= 80 {
            "true_positive"
        } else if score >= 45 {
            "suspicious"
        } else if score >= 25 {
            "inconclusive"
        } else {
            "false_positive"
        }
    }

    fn confidence_for(score: u32, evidence_count: usize) -> f64 {
        let distance_from_boundary = if score >= 80 {
            score - 80
        } else if score >= 45 {
            (score - 45).min(80 - score)
        } else {
            45 - score
        };

        let base = 0.58 + (distance_from_boundary as f64 / 100.0);
        let evidence_bonus = (evidence_count as f64 * 0.03).min(0.18);

        (base + evidence_bonus).clamp(0.55, 0.98)
    }

    fn ip_regex() -> Option<&'static Regex> {
        static INSTANCE: OnceLock<Result<Regex, regex::Error>> = OnceLock::new();
        INSTANCE
            .get_or_init(|| Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"))
            .as_ref()
            .ok()
    }

    fn hash_regex() -> Option<&'static Regex> {
        static INSTANCE: OnceLock<Result<Regex, regex::Error>> = OnceLock::new();
        INSTANCE
            .get_or_init(|| Regex::new(r"\b[a-fA-F0-9]{64}\b"))
            .as_ref()
            .ok()
    }

    fn domain_regex() -> Option<&'static Regex> {
        static INSTANCE: OnceLock<Result<Regex, regex::Error>> = OnceLock::new();
        INSTANCE
            .get_or_init(|| {
                Regex::new(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b")
            })
            .as_ref()
            .ok()
    }

    fn extract_iocs(context: &IncidentContextInput) -> Vec<String> {
        let mut collected = Vec::new();
        let mut seen = HashSet::new();

        let mut add = |value: String| {
            let normalized = value.trim().to_ascii_lowercase();
            if !normalized.is_empty() && seen.insert(normalized) {
                collected.push(value);
            }
        };

        for indicator in &context.indicators {
            add(indicator.clone());
        }

        for url in &context.urls {
            add(url.clone());
        }

        if let Some(source_ip) = context.source_ip.as_ref() {
            add(source_ip.clone());
        }

        for text in [context.title.as_deref(), context.description.as_deref()]
            .into_iter()
            .flatten()
        {
            if let Some(pattern) = Self::ip_regex() {
                for capture in pattern.find_iter(text) {
                    add(capture.as_str().to_string());
                }
            }

            if let Some(pattern) = Self::hash_regex() {
                for capture in pattern.find_iter(text) {
                    add(capture.as_str().to_string());
                }
            }

            if let Some(pattern) = Self::domain_regex() {
                for capture in pattern.find_iter(text) {
                    let candidate = capture.as_str();
                    if !candidate.contains('@') {
                        add(candidate.to_string());
                    }
                }
            }
        }

        collected
    }

    fn map_mitre(context: &IncidentContextInput, score: u32) -> Vec<String> {
        let mut mapped = Vec::new();

        if !context.urls.is_empty() {
            mapped.push("T1566.002 - Spearphishing Link".to_string());
        }

        if Self::risky_attachment_count(&context.attachments) > 0 {
            mapped.push("T1566.001 - Spearphishing Attachment".to_string());
            mapped.push("T1204.002 - Malicious File".to_string());
        }

        if context.authentication_failures {
            mapped.push("T1078 - Valid Accounts".to_string());
        }

        if context.sender.is_some() {
            mapped.push("T1586.002 - Email Accounts".to_string());
        }

        if score >= 80 {
            mapped.push("T1059 - Command and Scripting Interpreter".to_string());
        }

        mapped.sort();
        mapped.dedup();
        mapped
    }

    fn recommended_actions(
        context: &IncidentContextInput,
        verdict: &str,
        score: u32,
    ) -> Vec<String> {
        let mut actions = Vec::new();

        let mut add_action = |action: &str| {
            if !actions.contains(&action.to_string()) {
                actions.push(action.to_string());
            }
        };

        if !context.urls.is_empty() {
            add_action("lookup_urls");
        }

        if !context.attachments.is_empty() {
            add_action("lookup_attachments");
        }

        match verdict {
            "true_positive" => {
                add_action("quarantine_email");
                add_action("disable_user");
                add_action("block_sender");
                add_action("create_ticket");
                add_action("notify_user");
            }
            "suspicious" => {
                add_action("quarantine_email");
                add_action("create_ticket");
                add_action("notify_user");
            }
            "inconclusive" => {
                add_action("create_ticket");
                add_action("notify_reporter");
            }
            _ => {
                add_action("notify_reporter");
                if score <= 20 {
                    add_action("log_false_positive");
                }
            }
        }

        actions
    }

    fn build_analysis(
        incident_id: &str,
        verdict: &str,
        risk_score: u32,
        evidence: &[String],
    ) -> String {
        format!(
            "Automated triage for incident {} produced verdict '{}' with risk score {}. Evidence: {}.",
            incident_id,
            verdict,
            risk_score,
            evidence.join("; ")
        )
    }

    fn analyze_incident(
        incident_id: &str,
        incident_context: &IncidentContextInput,
        agent_config: &AgentConfig,
    ) -> TriageResult {
        let (risk_score, evidence) = Self::calculate_risk_score(incident_context);
        let verdict = Self::classify_verdict(risk_score).to_string();
        let confidence = Self::confidence_for(risk_score, evidence.len());

        let iocs = if agent_config.extract_iocs {
            Self::extract_iocs(incident_context)
        } else {
            Vec::new()
        };

        let mitre_techniques = if agent_config.map_mitre {
            Self::map_mitre(incident_context, risk_score)
        } else {
            Vec::new()
        };

        TriageResult {
            verdict: verdict.clone(),
            confidence,
            analysis: Self::build_analysis(incident_id, &verdict, risk_score, &evidence),
            recommended_actions: Self::recommended_actions(incident_context, &verdict, risk_score),
            risk_score,
            iocs,
            mitre_techniques,
        }
    }
}

impl Default for RunTriageAgentAction {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Action for RunTriageAgentAction {
    fn name(&self) -> &str {
        "run_triage_agent"
    }

    fn description(&self) -> &str {
        "Runs triage analysis for an incident using AI service or heuristic fallback"
    }

    fn required_parameters(&self) -> Vec<ParameterDef> {
        vec![
            ParameterDef::required(
                "incident_id",
                "The ID of the incident to triage",
                ParameterType::String,
            ),
            ParameterDef::optional(
                "agent_config",
                "Optional triage configuration (model, max_tokens, temperature, extract_iocs, map_mitre)",
                ParameterType::Object,
                serde_json::json!({}),
            ),
            ParameterDef::optional(
                "incident_context",
                "Optional context for scoring (title, description, severity, sender, URLs, attachments, indicators)",
                ParameterType::Object,
                serde_json::json!({}),
            ),
            ParameterDef::optional(
                "triage_service_url",
                "Optional override URL for the AI triage service (defaults to TW_TRIAGE_SERVICE_URL)",
                ParameterType::String,
                serde_json::Value::Null,
            ),
        ]
    }

    fn supports_rollback(&self) -> bool {
        // Triage analysis cannot be rolled back - it is non-destructive.
        false
    }

    #[instrument(skip(self, context))]
    async fn execute(&self, context: ActionContext) -> Result<ActionResult, ActionError> {
        let started_at = Utc::now();
        let incident_id = context.require_string("incident_id")?;

        let agent_config: AgentConfig = match context.get_param("agent_config") {
            Some(value) => serde_json::from_value(value.clone()).map_err(|err| {
                ActionError::InvalidParameters(format!("Invalid agent_config: {}", err))
            })?,
            None => AgentConfig::default(),
        };

        Self::validate_agent_config(&agent_config)?;

        let incident_context = Self::parse_incident_context(&context)?;

        // Determine which triage path to use: AI service or heuristic.
        let service_url = self.resolve_service_url(&context);

        let (triage_result, model_used) = if let Some(url) = service_url {
            // Try AI triage service
            match self.call_triage_service(&url, &incident_context).await {
                Ok(resp) => {
                    let model = resp.analyzed_by.clone();
                    let (result, _severity, _tokens, _exec_time) =
                        Self::service_response_to_result(resp);
                    info!(
                        incident_id = %incident_id,
                        "AI triage service returned verdict: {}",
                        result.verdict
                    );
                    (
                        result,
                        if model.is_empty() {
                            "react-agent".to_string()
                        } else {
                            model
                        },
                    )
                }
                Err(err) => {
                    warn!(
                        incident_id = %incident_id,
                        error = %err,
                        "AI triage service failed, falling back to heuristic"
                    );
                    let result =
                        Self::analyze_incident(&incident_id, &incident_context, &agent_config);
                    (result, "heuristic-v1 (fallback)".to_string())
                }
            }
        } else {
            // No service URL — use heuristic directly
            let result = Self::analyze_incident(&incident_id, &incident_context, &agent_config);
            let model = agent_config
                .model
                .clone()
                .unwrap_or_else(|| "heuristic-v1".to_string());
            (result, model)
        };

        let triage_id = format!("triage-{}", uuid::Uuid::new_v4());

        info!(
            "Triage {} completed for incident {} with verdict: {} (confidence: {:.2})",
            triage_id, incident_id, triage_result.verdict, triage_result.confidence
        );

        let mut output = HashMap::new();
        output.insert("triage_id".to_string(), serde_json::json!(triage_id));
        output.insert("incident_id".to_string(), serde_json::json!(incident_id));
        output.insert("model_used".to_string(), serde_json::json!(model_used));
        output.insert(
            "verdict".to_string(),
            serde_json::json!(triage_result.verdict),
        );
        output.insert(
            "confidence".to_string(),
            serde_json::json!(triage_result.confidence),
        );
        output.insert(
            "analysis".to_string(),
            serde_json::json!(triage_result.analysis),
        );
        output.insert(
            "recommended_actions".to_string(),
            serde_json::json!(triage_result.recommended_actions),
        );
        output.insert(
            "risk_score".to_string(),
            serde_json::json!(triage_result.risk_score),
        );
        output.insert("iocs".to_string(), serde_json::json!(triage_result.iocs));
        output.insert(
            "mitre_techniques".to_string(),
            serde_json::json!(triage_result.mitre_techniques),
        );

        Ok(ActionResult::success(
            self.name(),
            &format!(
                "Triage completed: verdict={}, confidence={:.2}, risk_score={}",
                output["verdict"].as_str().unwrap_or("unknown"),
                output["confidence"].as_f64().unwrap_or_default(),
                output["risk_score"].as_u64().unwrap_or_default()
            ),
            started_at,
            output,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use uuid::Uuid;

    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    #[tokio::test]
    async fn test_run_triage_agent() {
        let action = RunTriageAgentAction::new();

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("incident_id", serde_json::json!("INC-2024-001"));

        let result = action.execute(context).await.unwrap();
        assert!(result.success);
        assert!(!result.rollback_available);
        assert!(result.output.contains_key("triage_id"));
        assert!(result.output.contains_key("verdict"));
        assert!(result.output.contains_key("confidence"));
        assert!(result.output.contains_key("analysis"));
        assert!(result.output.contains_key("recommended_actions"));
        assert!(result.output.contains_key("risk_score"));
    }

    #[tokio::test]
    async fn test_run_triage_agent_with_config() {
        let action = RunTriageAgentAction::new();

        let config = serde_json::json!({
            "model": "heuristic-v1",
            "max_tokens": 2000,
            "temperature": 0.7,
            "extract_iocs": true,
            "map_mitre": true
        });

        let incident_context = serde_json::json!({
            "severity": "high",
            "title": "Urgent password reset",
            "description": "Please verify your account at http://bit.ly/reset-now",
            "urls": ["http://bit.ly/reset-now"],
            "attachments": ["invoice.exe"],
            "source_ip": "203.0.113.10"
        });

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("incident_id", serde_json::json!("INC-2024-002"))
            .with_param("agent_config", config)
            .with_param("incident_context", incident_context);

        let result = action.execute(context).await.unwrap();
        assert!(result.success);

        let verdict = result.output["verdict"].as_str().unwrap();
        assert!(matches!(
            verdict,
            "true_positive" | "suspicious" | "false_positive" | "inconclusive"
        ));

        let confidence = result.output["confidence"].as_f64().unwrap();
        assert!((0.0..=1.0).contains(&confidence));

        let risk_score = result.output["risk_score"].as_u64().unwrap();
        assert!(risk_score <= 100);

        let iocs = result.output["iocs"].as_array().unwrap();
        assert!(!iocs.is_empty());

        let techniques = result.output["mitre_techniques"].as_array().unwrap();
        assert!(!techniques.is_empty());
    }

    #[tokio::test]
    async fn test_run_triage_agent_no_rollback() {
        let action = RunTriageAgentAction::new();
        assert!(!action.supports_rollback());
    }

    #[tokio::test]
    async fn test_run_triage_agent_missing_incident_id() {
        let action = RunTriageAgentAction::new();

        let context = ActionContext::new(Uuid::new_v4());

        let result = action.execute(context).await;
        assert!(matches!(result, Err(ActionError::InvalidParameters(_))));
    }

    #[tokio::test]
    async fn test_triage_result_contains_iocs_when_enabled() {
        let action = RunTriageAgentAction::new();

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("incident_id", serde_json::json!("INC-2024-003"))
            .with_param(
                "agent_config",
                serde_json::json!({"extract_iocs": true, "map_mitre": false}),
            )
            .with_param(
                "incident_context",
                serde_json::json!({
                    "description": "Connection to 198.51.100.10 and evil.example",
                    "urls": ["https://evil.example/login"]
                }),
            );

        let result = action.execute(context).await.unwrap();

        let iocs = result.output["iocs"].as_array().unwrap();
        assert!(!iocs.is_empty());
    }

    #[tokio::test]
    async fn test_triage_result_contains_mitre_techniques_when_enabled() {
        let action = RunTriageAgentAction::new();

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("incident_id", serde_json::json!("INC-2024-004"))
            .with_param(
                "agent_config",
                serde_json::json!({"extract_iocs": false, "map_mitre": true}),
            )
            .with_param(
                "incident_context",
                serde_json::json!({
                    "authentication_failures": true,
                    "attachments": ["payload.js"],
                    "urls": ["https://phish.example/login"]
                }),
            );

        let result = action.execute(context).await.unwrap();

        let techniques = result.output["mitre_techniques"].as_array().unwrap();
        assert!(!techniques.is_empty());
    }

    #[tokio::test]
    async fn test_invalid_agent_config_rejected() {
        let action = RunTriageAgentAction::new();

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("incident_id", serde_json::json!("INC-2024-005"))
            .with_param(
                "agent_config",
                serde_json::json!({"max_tokens": 0, "temperature": 4.5}),
            );

        let result = action.execute(context).await;
        assert!(matches!(result, Err(ActionError::InvalidParameters(_))));
    }

    #[test]
    fn test_default_agent_config() {
        let config = AgentConfig::default();
        assert!(config.model.is_none());
        assert!(config.max_tokens.is_none());
        assert!(config.temperature.is_none());
        assert!(!config.extract_iocs);
        assert!(!config.map_mitre);
    }

    #[tokio::test]
    async fn test_fallback_when_service_url_unreachable() {
        let action =
            RunTriageAgentAction::new().with_triage_service_url("http://127.0.0.1:1".to_string());

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("incident_id", serde_json::json!("INC-FALLBACK-001"))
            .with_param(
                "incident_context",
                serde_json::json!({
                    "severity": "high",
                    "title": "Test fallback"
                }),
            );

        let result = action.execute(context).await.unwrap();
        assert!(result.success);
        // Should have fallen back to heuristic
        let model = result.output["model_used"].as_str().unwrap();
        assert!(
            model.contains("heuristic"),
            "Expected heuristic fallback, got: {}",
            model
        );
    }

    #[tokio::test]
    async fn test_service_url_from_metadata() {
        // When triage_service_url is passed via metadata instead of struct field
        let action = RunTriageAgentAction::new();

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("incident_id", serde_json::json!("INC-META-001"))
            .with_metadata(
                "triage_service_url",
                serde_json::json!("http://127.0.0.1:1"),
            )
            .with_param("incident_context", serde_json::json!({"severity": "low"}));

        // Should fall back to heuristic since URL is unreachable
        let result = action.execute(context).await.unwrap();
        assert!(result.success);
        let model = result.output["model_used"].as_str().unwrap();
        assert!(
            model.contains("heuristic"),
            "Expected heuristic fallback, got: {}",
            model
        );
    }

    #[test]
    fn test_infer_alert_type() {
        let action = RunTriageAgentAction::new();

        let phishing = IncidentContextInput {
            sender: Some("bad@evil.com".to_string()),
            ..Default::default()
        };
        assert_eq!(action.infer_alert_type(&phishing), "phishing");

        let malware = IncidentContextInput {
            attachments: vec!["payload.exe".to_string()],
            ..Default::default()
        };
        assert_eq!(action.infer_alert_type(&malware), "malware");

        let brute = IncidentContextInput {
            authentication_failures: true,
            ..Default::default()
        };
        assert_eq!(action.infer_alert_type(&brute), "brute_force");

        let generic = IncidentContextInput::default();
        assert_eq!(action.infer_alert_type(&generic), "generic");
    }

    #[test]
    fn test_service_response_to_result() {
        let resp = TriageServiceResponse {
            verdict: "true_positive".to_string(),
            confidence: 0.92,
            severity: "high".to_string(),
            summary: "Phishing detected".to_string(),
            reasoning: "URL analysis confirmed typosquat".to_string(),
            indicators: vec![ServiceIndicator {
                indicator_type: "domain".to_string(),
                value: "paypa1.com".to_string(),
            }],
            mitre_techniques: vec![ServiceMitreTechnique {
                id: "T1566.002".to_string(),
                name: "Spearphishing Link".to_string(),
            }],
            recommended_actions: vec![ServiceRecommendedAction {
                action: "quarantine_email".to_string(),
            }],
            analyzed_by: "react-agent".to_string(),
            tokens_used: 1500,
            execution_time_seconds: 3.2,
        };

        let (result, severity, tokens_used, exec_time) =
            RunTriageAgentAction::service_response_to_result(resp);
        assert_eq!(result.verdict, "true_positive");
        assert!((result.confidence - 0.92).abs() < f64::EPSILON);
        assert_eq!(result.risk_score, 92);
        assert_eq!(result.iocs, vec!["domain:paypa1.com"]);
        assert_eq!(
            result.mitre_techniques,
            vec!["T1566.002 - Spearphishing Link"]
        );
        assert_eq!(result.recommended_actions, vec!["quarantine_email"]);
        assert!(result.analysis.contains("Phishing detected"));
        assert!(result.analysis.contains("URL analysis confirmed"));
        assert_eq!(severity, "high");
        assert_eq!(tokens_used, 1500);
        assert!((exec_time - 3.2).abs() < f64::EPSILON);
    }

    #[test]
    fn test_service_response_normalizes_legacy_verdicts() {
        let resp = TriageServiceResponse {
            verdict: "malicious".to_string(),
            confidence: 0.87,
            severity: "high".to_string(),
            summary: "Detected".to_string(),
            reasoning: String::new(),
            indicators: vec![],
            mitre_techniques: vec![],
            recommended_actions: vec![],
            analyzed_by: "react-agent".to_string(),
            tokens_used: 0,
            execution_time_seconds: 0.1,
        };

        let (result, _, _, _) = RunTriageAgentAction::service_response_to_result(resp);
        assert_eq!(result.verdict, "true_positive");
    }

    #[tokio::test]
    async fn test_service_url_from_env_when_not_explicitly_overridden() {
        let _env_lock = ENV_MUTEX.lock().expect("env mutex poisoned");
        let previous = std::env::var("TW_TRIAGE_SERVICE_URL").ok();
        std::env::set_var("TW_TRIAGE_SERVICE_URL", "http://127.0.0.1:1");

        let action = RunTriageAgentAction::new();
        let context = ActionContext::new(Uuid::new_v4())
            .with_param("incident_id", serde_json::json!("INC-ENV-001"))
            .with_param("incident_context", serde_json::json!({"severity": "low"}));

        let result = action.execute(context).await.unwrap();
        assert!(result.success);
        let model = result.output["model_used"].as_str().unwrap();
        assert!(
            model.contains("heuristic"),
            "Expected heuristic fallback, got: {}",
            model
        );

        if let Some(previous) = previous {
            std::env::set_var("TW_TRIAGE_SERVICE_URL", previous);
        } else {
            std::env::remove_var("TW_TRIAGE_SERVICE_URL");
        }
    }

    #[tokio::test]
    async fn test_action_param_service_url_override_precedence() {
        let _env_lock = ENV_MUTEX.lock().expect("env mutex poisoned");
        let previous = std::env::var("TW_TRIAGE_SERVICE_URL").ok();
        // Context parameter should override env and metadata.
        std::env::set_var("TW_TRIAGE_SERVICE_URL", "http://env-invalid:1");
        let action = RunTriageAgentAction::new();

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("incident_id", serde_json::json!("INC-OVERRIDE-001"))
            .with_metadata(
                "triage_service_url",
                serde_json::json!("http://metadata-invalid:1"),
            )
            .with_param(
                "triage_service_url",
                serde_json::json!("http://127.0.0.1:1"),
            )
            .with_param(
                "incident_context",
                serde_json::json!({"severity": "medium"}),
            );

        let result = action.execute(context).await.unwrap();
        assert!(result.success);
        let model = result.output["model_used"].as_str().unwrap();
        assert!(
            model.contains("heuristic"),
            "Expected heuristic fallback, got: {}",
            model
        );

        if let Some(previous) = previous {
            std::env::set_var("TW_TRIAGE_SERVICE_URL", previous);
        } else {
            std::env::remove_var("TW_TRIAGE_SERVICE_URL");
        }
    }
}
