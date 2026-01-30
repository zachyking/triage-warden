"""Phishing email triage workflow orchestrator for Triage Warden.

This module provides a complete workflow for triaging phishing email alerts,
including:
- Email parsing and analysis
- Phishing indicator detection
- Sender reputation checks
- URL safety verification
- Risk-based automated decision making
- Response action execution (quarantine, block, notify)
- AI-powered triage with ReAct agent integration
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any, Literal

import structlog

from tw_ai.analysis.email import EmailAnalysis, parse_email_alert
from tw_ai.analysis.phishing import PhishingIndicators, analyze_phishing_indicators

# Conditional imports for AI-integrated workflow
if TYPE_CHECKING:
    pass

logger = structlog.get_logger()


# =============================================================================
# AI Workflow Stage Constants
# =============================================================================

STAGE_PARSE = "PARSE"
STAGE_ANALYZE = "ANALYZE"
STAGE_ENRICH = "ENRICH"
STAGE_DECIDE = "DECIDE"
STAGE_APPROVE = "APPROVE"


# =============================================================================
# Enums and Constants
# =============================================================================


class TriageDecision(str, Enum):
    """Possible triage decisions for a phishing email."""

    QUARANTINE = "quarantine"
    BLOCK_SENDER = "block_sender"
    NEEDS_REVIEW = "needs_review"
    BENIGN = "benign"


class WorkflowStage(str, Enum):
    """Stages of the phishing triage workflow."""

    INITIALIZED = "initialized"
    PARSING = "parsing"
    ANALYZING_PHISHING = "analyzing_phishing"
    CHECKING_REPUTATION = "checking_reputation"
    CHECKING_URLS = "checking_urls"
    MAKING_DECISION = "making_decision"
    EXECUTING_ACTIONS = "executing_actions"
    COMPLETED = "completed"
    FAILED = "failed"


# =============================================================================
# Data Classes
# =============================================================================


@dataclass
class DecisionThresholds:
    """Configurable thresholds for automated triage decisions.

    Attributes:
        auto_quarantine_score: Minimum risk score for auto quarantine (default: 80)
        auto_block_score: Minimum risk score for auto sender blocking (default: 90)
        needs_review_score: Minimum risk score requiring human review (default: 40)
        min_confidence_for_action: Min confidence for automated actions (default: 0.85)
        sender_reputation_low_threshold: Score below which is suspicious (default: 30)
    """

    auto_quarantine_score: int = 80
    auto_block_score: int = 90
    needs_review_score: int = 40
    min_confidence_for_action: float = 0.85
    sender_reputation_low_threshold: int = 30

    def __post_init__(self):
        """Validate threshold values."""
        if not 0 <= self.auto_quarantine_score <= 100:
            raise ValueError("auto_quarantine_score must be between 0 and 100")
        if not 0 <= self.auto_block_score <= 100:
            raise ValueError("auto_block_score must be between 0 and 100")
        if not 0 <= self.needs_review_score <= 100:
            raise ValueError("needs_review_score must be between 0 and 100")
        if not 0.0 <= self.min_confidence_for_action <= 1.0:
            raise ValueError("min_confidence_for_action must be between 0.0 and 1.0")
        if self.needs_review_score >= self.auto_quarantine_score:
            raise ValueError("needs_review_score must be less than auto_quarantine_score")


@dataclass
class ActionResult:
    """Result of a response action execution.

    Attributes:
        action_type: Type of action executed
        success: Whether the action succeeded
        action_id: Unique identifier for the action
        target: Target of the action (message_id, sender, etc.)
        message: Human-readable result message
        error: Error message if action failed
    """

    action_type: str
    success: bool
    action_id: str | None = None
    target: str | None = None
    message: str | None = None
    error: str | None = None


@dataclass
class URLCheckResult:
    """Result of a URL safety check.

    Attributes:
        url: The URL that was checked
        domain: Domain portion of the URL
        verdict: Safety verdict (malicious, suspicious, clean, unknown)
        score: Threat score (0-100)
        categories: Threat categories if malicious/suspicious
        is_mock: Whether this is mock data
    """

    url: str
    domain: str
    verdict: str
    score: int = 0
    categories: list[str] = field(default_factory=list)
    is_mock: bool = True


@dataclass
class SenderReputationResult:
    """Result of a sender reputation check.

    Attributes:
        sender_email: Email address checked
        domain: Domain portion of the email
        score: Reputation score (0-100, higher is better)
        is_known_sender: Whether sender is in known/trusted list
        domain_age_days: Age of the domain in days
        risk_level: Risk level (low, medium, high)
        is_mock: Whether this is mock data
    """

    sender_email: str
    domain: str
    score: int
    is_known_sender: bool
    domain_age_days: int | None
    risk_level: str
    is_mock: bool = True


@dataclass
class WorkflowResult:
    """Result of the phishing triage workflow.

    Attributes:
        decision: The triage decision made
        confidence: Confidence in the decision (0-1)
        risk_score: Overall risk score (0-100)
        actions_taken: List of actions executed
        analysis_summary: Human-readable summary of the analysis
        workflow_id: Unique identifier for this workflow run
        execution_time_seconds: Total execution time
        email_analysis: Parsed email analysis data
        phishing_indicators: Detected phishing indicators
        sender_reputation: Sender reputation check result
        url_checks: Results of URL safety checks
        stage: Final workflow stage
        error: Error message if workflow failed
    """

    decision: TriageDecision
    confidence: float
    risk_score: int
    actions_taken: list[ActionResult]
    analysis_summary: str
    workflow_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    execution_time_seconds: float = 0.0
    email_analysis: dict[str, Any] | None = None
    phishing_indicators: dict[str, Any] | None = None
    sender_reputation: SenderReputationResult | None = None
    url_checks: list[URLCheckResult] = field(default_factory=list)
    stage: WorkflowStage = WorkflowStage.COMPLETED
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert result to dictionary for serialization."""
        return {
            "decision": self.decision.value,
            "confidence": self.confidence,
            "risk_score": self.risk_score,
            "actions_taken": [
                {
                    "action_type": a.action_type,
                    "success": a.success,
                    "action_id": a.action_id,
                    "target": a.target,
                    "message": a.message,
                    "error": a.error,
                }
                for a in self.actions_taken
            ],
            "analysis_summary": self.analysis_summary,
            "workflow_id": self.workflow_id,
            "execution_time_seconds": self.execution_time_seconds,
            "email_analysis": self.email_analysis,
            "phishing_indicators": self.phishing_indicators,
            "sender_reputation": (
                {
                    "sender_email": self.sender_reputation.sender_email,
                    "domain": self.sender_reputation.domain,
                    "score": self.sender_reputation.score,
                    "is_known_sender": self.sender_reputation.is_known_sender,
                    "domain_age_days": self.sender_reputation.domain_age_days,
                    "risk_level": self.sender_reputation.risk_level,
                }
                if self.sender_reputation
                else None
            ),
            "url_checks": [
                {
                    "url": u.url,
                    "domain": u.domain,
                    "verdict": u.verdict,
                    "score": u.score,
                    "categories": u.categories,
                }
                for u in self.url_checks
            ],
            "stage": self.stage.value,
            "error": self.error,
        }


# =============================================================================
# AI-Integrated Triage Result
# =============================================================================


@dataclass
class TriageResult:
    """Result of the AI-integrated phishing triage workflow.

    This dataclass is returned by the triage() method which uses the ReAct
    agent for AI-powered decision making.

    Attributes:
        verdict: The triage verdict (malicious/suspicious/benign/inconclusive)
        confidence: Confidence score from 0-100
        analysis: TriageAnalysis from the ReAct agent (if successful)
        email_analysis: Parsed email data
        phishing_indicators: Detected phishing indicators
        proposed_actions: Actions proposed by the agent
        approved_actions: Actions approved by policy
        rejected_actions: Actions rejected by policy
        execution_time_seconds: Total execution time
        stages_completed: List of successfully completed stages
        error: Error message if workflow failed
    """

    verdict: str
    confidence: float
    analysis: Any | None = None  # TriageAnalysis from agents.models
    email_analysis: EmailAnalysis | None = None
    phishing_indicators: PhishingIndicators | None = None
    proposed_actions: list[dict] = field(default_factory=list)
    approved_actions: list[dict] = field(default_factory=list)
    rejected_actions: list[dict] = field(default_factory=list)
    execution_time_seconds: float = 0.0
    stages_completed: list[str] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert result to dictionary for serialization."""
        return {
            "verdict": self.verdict,
            "confidence": self.confidence,
            "analysis": (
                self.analysis.model_dump()
                if self.analysis and hasattr(self.analysis, "model_dump")
                else None
            ),
            "email_analysis": self._email_analysis_to_dict(),
            "phishing_indicators": self._phishing_indicators_to_dict(),
            "proposed_actions": self.proposed_actions,
            "approved_actions": self.approved_actions,
            "rejected_actions": self.rejected_actions,
            "execution_time_seconds": self.execution_time_seconds,
            "stages_completed": self.stages_completed,
            "error": self.error,
        }

    def _email_analysis_to_dict(self) -> dict[str, Any] | None:
        """Convert EmailAnalysis to dictionary."""
        if self.email_analysis is None:
            return None
        return {
            "message_id": self.email_analysis.message_id,
            "subject": self.email_analysis.subject,
            "sender": self.email_analysis.sender,
            "sender_display_name": self.email_analysis.sender_display_name,
            "reply_to": self.email_analysis.reply_to,
            "recipients": self.email_analysis.recipients,
            "cc": self.email_analysis.cc,
            "url_count": len(self.email_analysis.urls),
            "attachment_count": len(self.email_analysis.attachments),
            "authentication": {
                "spf": self.email_analysis.authentication.spf,
                "dkim": self.email_analysis.authentication.dkim,
                "dmarc": self.email_analysis.authentication.dmarc,
            },
        }

    def _phishing_indicators_to_dict(self) -> dict[str, Any] | None:
        """Convert PhishingIndicators to dictionary."""
        if self.phishing_indicators is None:
            return None
        return {
            "overall_risk_score": self.phishing_indicators.overall_risk_score,
            "typosquat_domains": [
                {
                    "suspicious_domain": m.suspicious_domain,
                    "similar_to": m.similar_to,
                    "similarity_score": m.similarity_score,
                    "technique": m.technique,
                }
                for m in self.phishing_indicators.typosquat_domains
            ],
            "urgency_phrases": self.phishing_indicators.urgency_phrases,
            "credential_request_detected": self.phishing_indicators.credential_request_detected,
            "suspicious_urls": self.phishing_indicators.suspicious_urls,
            "url_text_mismatch": self.phishing_indicators.url_text_mismatch,
            "sender_domain_mismatch": self.phishing_indicators.sender_domain_mismatch,
            "attachment_risk_level": self.phishing_indicators.attachment_risk_level,
            "risk_factors": self.phishing_indicators.risk_factors,
        }


# =============================================================================
# Phishing Triage Workflow
# =============================================================================


class PhishingTriageWorkflow:
    """Orchestrates the complete phishing email triage process.

    This workflow supports two modes:
    1. Rule-based mode (run method): Uses configurable thresholds for automated decisions
    2. AI-integrated mode (triage method): Uses ReAct agent for AI-powered decisions

    Rule-based workflow stages:
    1. Parses incoming email alerts
    2. Analyzes email for phishing indicators
    3. Checks sender reputation and URL safety
    4. Makes automated triage decisions based on risk scores
    5. Executes appropriate response actions (quarantine, block, notify)

    AI-integrated workflow stages:
    1. PARSE: Parse email from alert using parse_email_alert()
    2. ANALYZE: Run phishing indicator analysis
    3. ENRICH: Lookup URLs and sender domain via tools
    4. DECIDE: Run ReAct agent with phishing prompt
    5. APPROVE: Check each proposed action against policy

    Example (rule-based):
        workflow = PhishingTriageWorkflow()
        result = await workflow.run({
            "message_id": "msg-123",
            "subject": "Urgent: Verify your account",
            "sender": "security@paypa1.com",
            "body_text": "Click here to verify: http://evil.example.com",
            "recipients": ["user@company.com"],
        })
        print(f"Decision: {result.decision}, Risk: {result.risk_score}")

    Example (AI-integrated):
        from tw_ai.agents.react import ReActAgent
        from tw_ai.agents.tools import create_triage_tools

        agent = ReActAgent(llm=provider, tools=registry)
        tools = create_triage_tools()
        workflow = PhishingTriageWorkflow(agent=agent, tools=tools)

        result = await workflow.triage({...})
        print(f"Verdict: {result.verdict}, Confidence: {result.confidence}")
    """

    def __init__(
        self,
        thresholds: DecisionThresholds | None = None,
        enable_actions: bool = True,
        dry_run: bool = False,
        # AI-integrated mode parameters
        agent: Any | None = None,  # ReActAgent
        tools: Any | None = None,  # ToolRegistry
        policy_checker: Callable[[dict], dict] | None = None,
        on_stage_complete: Callable[[str, Any], None] | None = None,
    ):
        """Initialize the phishing triage workflow.

        Args:
            thresholds: Custom decision thresholds. Uses defaults if not provided.
            enable_actions: Whether to execute response actions. Default True.
            dry_run: If True, simulate actions without actually executing. Default False.
            agent: ReActAgent for AI-driven decision making (enables triage() method).
            tools: ToolRegistry for URL/domain lookups in AI mode.
            policy_checker: Function to check if actions are allowed by policy.
                           Takes action dict, returns dict with 'decision' key
                           ('allowed', 'denied', 'requires_approval') and
                           optional 'reason' key.
            on_stage_complete: Callback for stage completion events in AI mode.
                              Called with (stage_name, stage_data).
        """
        # Rule-based mode settings
        self.thresholds = thresholds or DecisionThresholds()
        self.enable_actions = enable_actions
        self.dry_run = dry_run
        self._current_stage = WorkflowStage.INITIALIZED

        # AI-integrated mode settings
        self.agent = agent
        self.tools = tools
        self.policy_checker = policy_checker
        self._on_stage_complete = on_stage_complete

        logger.info(
            "phishing_workflow_initialized",
            thresholds={
                "auto_quarantine_score": self.thresholds.auto_quarantine_score,
                "auto_block_score": self.thresholds.auto_block_score,
                "needs_review_score": self.thresholds.needs_review_score,
            },
            enable_actions=enable_actions,
            dry_run=dry_run,
            ai_mode_enabled=agent is not None,
        )

    async def run(self, email_alert: dict[str, Any]) -> WorkflowResult:
        """Execute the complete phishing triage workflow.

        Args:
            email_alert: Raw email alert data containing:
                - message_id: Unique message identifier
                - subject: Email subject
                - sender or from: Sender address
                - recipients or to: Recipient addresses
                - body_text and/or body_html: Email body content
                - headers: Email headers (optional)
                - attachments: List of attachment info (optional)

        Returns:
            WorkflowResult with decision, risk score, actions taken, and analysis details.
        """
        workflow_id = str(uuid.uuid4())
        start_time = time.time()
        actions_taken: list[ActionResult] = []

        logger.info(
            "phishing_workflow_started",
            workflow_id=workflow_id,
            message_id=email_alert.get("message_id", "unknown"),
        )

        try:
            # Stage 1: Parse email
            self._current_stage = WorkflowStage.PARSING
            email_analysis = self._parse_email(email_alert)

            # Stage 2: Analyze phishing indicators
            self._current_stage = WorkflowStage.ANALYZING_PHISHING
            phishing_indicators = self._analyze_phishing(email_alert, email_analysis)

            # Stage 3: Check sender reputation
            self._current_stage = WorkflowStage.CHECKING_REPUTATION
            sender_reputation = await self._check_sender_reputation(email_analysis.sender)

            # Stage 4: Check URL safety
            self._current_stage = WorkflowStage.CHECKING_URLS
            url_checks = await self._check_urls(email_analysis)

            # Stage 5: Make decision
            self._current_stage = WorkflowStage.MAKING_DECISION
            decision, confidence, adjusted_risk_score = self._make_decision(
                phishing_indicators,
                sender_reputation,
                url_checks,
            )

            # Stage 6: Execute actions
            self._current_stage = WorkflowStage.EXECUTING_ACTIONS
            if self.enable_actions and decision != TriageDecision.BENIGN:
                actions_taken = await self._execute_actions(
                    decision,
                    confidence,
                    email_analysis,
                    phishing_indicators,
                    email_alert.get("message_id", ""),
                )

            # Build summary
            analysis_summary = self._build_summary(
                decision,
                confidence,
                adjusted_risk_score,
                phishing_indicators,
                sender_reputation,
                url_checks,
                actions_taken,
            )

            self._current_stage = WorkflowStage.COMPLETED
            execution_time = time.time() - start_time

            logger.info(
                "phishing_workflow_completed",
                workflow_id=workflow_id,
                decision=decision.value,
                confidence=confidence,
                risk_score=adjusted_risk_score,
                actions_count=len(actions_taken),
                execution_time_seconds=execution_time,
            )

            return WorkflowResult(
                decision=decision,
                confidence=confidence,
                risk_score=adjusted_risk_score,
                actions_taken=actions_taken,
                analysis_summary=analysis_summary,
                workflow_id=workflow_id,
                execution_time_seconds=execution_time,
                email_analysis=self._email_analysis_to_dict(email_analysis),
                phishing_indicators=self._phishing_indicators_to_dict(phishing_indicators),
                sender_reputation=sender_reputation,
                url_checks=url_checks,
                stage=self._current_stage,
            )

        except Exception as e:
            self._current_stage = WorkflowStage.FAILED
            execution_time = time.time() - start_time

            logger.error(
                "phishing_workflow_failed",
                workflow_id=workflow_id,
                stage=self._current_stage.value,
                error=str(e),
                exc_info=True,
            )

            return WorkflowResult(
                decision=TriageDecision.NEEDS_REVIEW,
                confidence=0.0,
                risk_score=0,
                actions_taken=actions_taken,
                analysis_summary=f"Workflow failed: {str(e)}. Manual review required.",
                workflow_id=workflow_id,
                execution_time_seconds=execution_time,
                stage=self._current_stage,
                error=str(e),
            )

    def _parse_email(self, email_alert: dict[str, Any]) -> EmailAnalysis:
        """Parse the email alert into structured data.

        Args:
            email_alert: Raw email alert dictionary.

        Returns:
            EmailAnalysis object with parsed email data.
        """
        logger.debug("parsing_email", message_id=email_alert.get("message_id"))

        analysis = parse_email_alert(email_alert)

        logger.debug(
            "email_parsed",
            sender=analysis.sender,
            subject=analysis.subject,
            url_count=len(analysis.urls),
            attachment_count=len(analysis.attachments),
        )

        return analysis

    def _analyze_phishing(
        self, email_alert: dict[str, Any], email_analysis: EmailAnalysis
    ) -> PhishingIndicators:
        """Analyze email for phishing indicators.

        Args:
            email_alert: Raw email alert dictionary.
            email_analysis: Parsed email analysis.

        Returns:
            PhishingIndicators with detected phishing signals.
        """
        logger.debug("analyzing_phishing_indicators")

        # Build the email_data dict expected by analyze_phishing_indicators
        phishing_data = {
            "subject": email_analysis.subject,
            "body": email_analysis.body_text or email_analysis.body_html or "",
            "sender_email": email_analysis.sender,
            "sender_display_name": email_analysis.sender_display_name or "",
            "reply_to": email_analysis.reply_to or "",
            "urls": [url.url for url in email_analysis.urls],
            "url_display_texts": [
                {"url": url.url, "display_text": url.display_text or ""}
                for url in email_analysis.urls
                if url.display_text
            ],
            "attachments": [att.filename for att in email_analysis.attachments],
        }

        indicators = analyze_phishing_indicators(phishing_data)

        logger.debug(
            "phishing_analysis_complete",
            risk_score=indicators.overall_risk_score,
            typosquat_count=len(indicators.typosquat_domains),
            urgency_phrase_count=len(indicators.urgency_phrases),
            credential_request=indicators.credential_request_detected,
        )

        return indicators

    async def _check_sender_reputation(self, sender_email: str) -> SenderReputationResult:
        """Check the reputation of the email sender.

        Args:
            sender_email: Sender's email address.

        Returns:
            SenderReputationResult with reputation data.
        """
        logger.debug("checking_sender_reputation", sender=sender_email)

        # Extract domain from email
        domain = ""
        if "@" in sender_email:
            domain = sender_email.split("@")[-1].lower().strip()

        # Mock reputation check - in production this would call a real service
        reputation_data = self._mock_sender_reputation(sender_email, domain)

        result = SenderReputationResult(
            sender_email=sender_email,
            domain=domain,
            score=reputation_data["score"],
            is_known_sender=reputation_data["is_known_sender"],
            domain_age_days=reputation_data["domain_age_days"],
            risk_level=reputation_data["risk_level"],
            is_mock=True,
        )

        logger.debug(
            "sender_reputation_checked",
            sender=sender_email,
            score=result.score,
            risk_level=result.risk_level,
        )

        return result

    def _mock_sender_reputation(self, sender_email: str, domain: str) -> dict[str, Any]:
        """Mock sender reputation lookup.

        Args:
            sender_email: Sender's email address.
            domain: Domain portion of the email.

        Returns:
            Dictionary with reputation data.
        """
        # Known trusted domains
        trusted_domains = {
            "google.com": {"score": 95, "domain_age_days": 9500, "category": "technology"},
            "microsoft.com": {"score": 95, "domain_age_days": 10000, "category": "technology"},
            "github.com": {"score": 90, "domain_age_days": 5800, "category": "technology"},
            "amazon.com": {"score": 92, "domain_age_days": 10500, "category": "e-commerce"},
            "apple.com": {"score": 95, "domain_age_days": 10000, "category": "technology"},
        }

        # Known suspicious domains
        suspicious_domains = {
            "evil.example.com": {"score": 5, "domain_age_days": 7},
            "phishing.bad": {"score": 0, "domain_age_days": 3},
            "malware.test": {"score": 10, "domain_age_days": 14},
        }

        if domain in trusted_domains:
            info = trusted_domains[domain]
            return {
                "score": info["score"],
                "is_known_sender": True,
                "domain_age_days": info["domain_age_days"],
                "risk_level": "low",
            }

        if domain in suspicious_domains:
            info = suspicious_domains[domain]
            return {
                "score": info["score"],
                "is_known_sender": False,
                "domain_age_days": info["domain_age_days"],
                "risk_level": "high",
            }

        # Check for suspicious patterns (typosquatting)
        suspicious_patterns = ["paypa1", "micros0ft", "g00gle", "amaz0n", "app1e"]
        for pattern in suspicious_patterns:
            if pattern in domain:
                return {
                    "score": 15,
                    "is_known_sender": False,
                    "domain_age_days": 30,
                    "risk_level": "high",
                }

        # Default: unknown sender
        return {
            "score": 50,
            "is_known_sender": False,
            "domain_age_days": None,
            "risk_level": "medium",
        }

    async def _check_urls(self, email_analysis: EmailAnalysis) -> list[URLCheckResult]:
        """Check safety of URLs in the email.

        Args:
            email_analysis: Parsed email analysis with extracted URLs.

        Returns:
            List of URLCheckResult for each URL.
        """
        logger.debug("checking_urls", url_count=len(email_analysis.urls))

        results: list[URLCheckResult] = []

        for extracted_url in email_analysis.urls:
            result = await self._check_single_url(extracted_url.url, extracted_url.domain)
            results.append(result)

        malicious_count = sum(1 for r in results if r.verdict == "malicious")
        suspicious_count = sum(1 for r in results if r.verdict == "suspicious")

        logger.debug(
            "url_checks_complete",
            total=len(results),
            malicious=malicious_count,
            suspicious=suspicious_count,
        )

        return results

    async def _check_single_url(self, url: str, domain: str) -> URLCheckResult:
        """Check safety of a single URL.

        Args:
            url: The URL to check.
            domain: Domain portion of the URL.

        Returns:
            URLCheckResult with safety verdict.
        """
        # Mock URL safety check - in production this would call a real service
        result = self._mock_url_check(url, domain)

        return URLCheckResult(
            url=url,
            domain=domain,
            verdict=result["verdict"],
            score=result["score"],
            categories=result.get("categories", []),
            is_mock=True,
        )

    def _mock_url_check(self, url: str, domain: str) -> dict[str, Any]:
        """Mock URL safety check.

        Args:
            url: The URL to check.
            domain: Domain portion of the URL.

        Returns:
            Dictionary with safety data.
        """
        # Known malicious domains
        malicious_domains = {"evil.example.com", "malware.test", "phishing.bad"}

        # Known safe domains
        safe_domains = {
            "google.com",
            "microsoft.com",
            "github.com",
            "amazon.com",
            "apple.com",
            "linkedin.com",
            "twitter.com",
            "facebook.com",
        }

        domain_lower = domain.lower()

        if domain_lower in malicious_domains:
            return {
                "verdict": "malicious",
                "score": 95,
                "categories": ["phishing", "malware"],
            }

        if domain_lower in safe_domains:
            return {
                "verdict": "clean",
                "score": 0,
                "categories": [],
            }

        # Check for IP-based URLs (suspicious)
        if domain_lower.replace(".", "").isdigit():
            return {
                "verdict": "suspicious",
                "score": 60,
                "categories": ["ip_based_url"],
            }

        # Check for suspicious patterns
        suspicious_patterns = ["paypa1", "micros0ft", "g00gle", "amaz0n", "app1e", "netfl1x"]
        for pattern in suspicious_patterns:
            if pattern in domain_lower:
                return {
                    "verdict": "suspicious",
                    "score": 75,
                    "categories": ["typosquatting"],
                }

        # Default: unknown
        return {
            "verdict": "unknown",
            "score": 30,
            "categories": [],
        }

    def _make_decision(
        self,
        phishing_indicators: PhishingIndicators,
        sender_reputation: SenderReputationResult,
        url_checks: list[URLCheckResult],
    ) -> tuple[TriageDecision, float, int]:
        """Make the triage decision based on all analysis results.

        Args:
            phishing_indicators: Detected phishing indicators.
            sender_reputation: Sender reputation check result.
            url_checks: URL safety check results.

        Returns:
            Tuple of (decision, confidence, adjusted_risk_score).
        """
        logger.debug("making_decision")

        # Start with phishing indicator risk score
        risk_score = phishing_indicators.overall_risk_score

        # Adjust based on sender reputation
        if sender_reputation.score < self.thresholds.sender_reputation_low_threshold:
            risk_score = min(100, risk_score + 15)

        if sender_reputation.risk_level == "high":
            risk_score = min(100, risk_score + 10)

        # Adjust based on URL checks
        malicious_urls = sum(1 for u in url_checks if u.verdict == "malicious")
        suspicious_urls = sum(1 for u in url_checks if u.verdict == "suspicious")

        if malicious_urls > 0:
            risk_score = min(100, risk_score + 25)
        if suspicious_urls > 0:
            risk_score = min(100, risk_score + 10)

        # Calculate confidence based on evidence strength
        confidence = self._calculate_confidence(
            phishing_indicators,
            sender_reputation,
            url_checks,
            risk_score,
        )

        # Make decision based on risk score and thresholds
        if (
            risk_score >= self.thresholds.auto_block_score
            and confidence >= self.thresholds.min_confidence_for_action
        ):
            decision = TriageDecision.BLOCK_SENDER
        elif (
            risk_score >= self.thresholds.auto_quarantine_score
            and confidence >= self.thresholds.min_confidence_for_action
        ):
            decision = TriageDecision.QUARANTINE
        elif risk_score >= self.thresholds.needs_review_score:
            decision = TriageDecision.NEEDS_REVIEW
        else:
            decision = TriageDecision.BENIGN

        logger.debug(
            "decision_made",
            decision=decision.value,
            confidence=confidence,
            risk_score=risk_score,
        )

        return decision, confidence, risk_score

    def _calculate_confidence(
        self,
        phishing_indicators: PhishingIndicators,
        sender_reputation: SenderReputationResult,
        url_checks: list[URLCheckResult],
        risk_score: int,
    ) -> float:
        """Calculate confidence in the triage decision.

        Args:
            phishing_indicators: Detected phishing indicators.
            sender_reputation: Sender reputation check result.
            url_checks: URL safety check results.
            risk_score: Adjusted risk score.

        Returns:
            Confidence score from 0.0 to 1.0.
        """
        confidence_factors: list[float] = []

        # Factor 1: Multiple phishing indicators detected
        indicator_count = sum(
            [
                len(phishing_indicators.typosquat_domains) > 0,
                len(phishing_indicators.urgency_phrases) > 0,
                phishing_indicators.credential_request_detected,
                len(phishing_indicators.suspicious_urls) > 0,
                phishing_indicators.url_text_mismatch,
                phishing_indicators.sender_domain_mismatch,
                phishing_indicators.attachment_risk_level in ("high", "critical"),
            ]
        )

        if indicator_count >= 4:
            confidence_factors.append(0.95)
        elif indicator_count >= 2:
            confidence_factors.append(0.80)
        elif indicator_count >= 1:
            confidence_factors.append(0.65)
        else:
            confidence_factors.append(0.50)

        # Factor 2: Sender reputation clarity
        if sender_reputation.is_known_sender and sender_reputation.score > 80:
            confidence_factors.append(0.95)  # High confidence it's legitimate
        elif sender_reputation.score < 20:
            confidence_factors.append(0.90)  # High confidence it's suspicious
        else:
            confidence_factors.append(0.60)  # Uncertain

        # Factor 3: URL check results
        malicious_urls = sum(1 for u in url_checks if u.verdict == "malicious")
        clean_urls = sum(1 for u in url_checks if u.verdict == "clean")

        if malicious_urls > 0:
            confidence_factors.append(0.95)
        elif clean_urls == len(url_checks) and len(url_checks) > 0:
            confidence_factors.append(0.85)
        elif len(url_checks) == 0:
            confidence_factors.append(0.70)
        else:
            confidence_factors.append(0.65)

        # Calculate weighted average
        if confidence_factors:
            avg_confidence = sum(confidence_factors) / len(confidence_factors)
        else:
            avg_confidence = 0.5

        # Adjust based on risk score extremes
        if risk_score >= 90:
            avg_confidence = min(1.0, avg_confidence * 1.1)
        elif risk_score <= 10:
            avg_confidence = min(1.0, avg_confidence * 1.1)

        return round(min(1.0, max(0.0, avg_confidence)), 2)

    async def _execute_actions(
        self,
        decision: TriageDecision,
        confidence: float,
        email_analysis: EmailAnalysis,
        phishing_indicators: PhishingIndicators,
        message_id: str,
    ) -> list[ActionResult]:
        """Execute response actions based on the decision.

        Args:
            decision: The triage decision.
            confidence: Confidence in the decision.
            email_analysis: Parsed email analysis.
            phishing_indicators: Detected phishing indicators.
            message_id: Email message identifier.

        Returns:
            List of ActionResult for executed actions.
        """
        actions: list[ActionResult] = []

        logger.debug(
            "executing_actions",
            decision=decision.value,
            dry_run=self.dry_run,
        )

        if decision == TriageDecision.QUARANTINE:
            result = await self._action_quarantine_email(
                message_id,
                phishing_indicators.risk_factors,
            )
            actions.append(result)

            # Also notify recipients
            for recipient in email_analysis.recipients[:5]:  # Limit to 5 recipients
                notify_result = await self._action_notify_user(
                    recipient,
                    email_analysis.subject,
                    "phishing_warning",
                )
                actions.append(notify_result)

        elif decision == TriageDecision.BLOCK_SENDER:
            # Quarantine the email first
            quarantine_result = await self._action_quarantine_email(
                message_id,
                phishing_indicators.risk_factors,
            )
            actions.append(quarantine_result)

            # Block the sender
            block_result = await self._action_block_sender(
                email_analysis.sender,
                "email",
                phishing_indicators.risk_factors,
            )
            actions.append(block_result)

            # Notify recipients
            for recipient in email_analysis.recipients[:5]:
                notify_result = await self._action_notify_user(
                    recipient,
                    email_analysis.subject,
                    "phishing_warning",
                )
                actions.append(notify_result)

        elif decision == TriageDecision.NEEDS_REVIEW:
            # Create a security ticket for review
            ticket_result = await self._action_create_ticket(
                email_analysis,
                phishing_indicators,
                confidence,
            )
            actions.append(ticket_result)

        return actions

    async def _action_quarantine_email(
        self,
        message_id: str,
        risk_factors: list[str],
    ) -> ActionResult:
        """Execute email quarantine action.

        Args:
            message_id: Email message identifier.
            risk_factors: List of detected risk factors.

        Returns:
            ActionResult for the quarantine action.
        """
        reason = "; ".join(risk_factors[:3]) if risk_factors else "Phishing indicators detected"

        if self.dry_run:
            logger.info(
                "dry_run_quarantine_email",
                message_id=message_id,
                reason=reason,
            )
            return ActionResult(
                action_type="quarantine_email",
                success=True,
                action_id=f"dry-run-{uuid.uuid4().hex[:8]}",
                target=message_id,
                message=f"[DRY RUN] Would quarantine email {message_id}",
            )

        # Mock action execution
        action_id = f"qe-{uuid.uuid4().hex[:12]}"

        logger.info(
            "quarantine_email_executed",
            action_id=action_id,
            message_id=message_id,
            reason=reason,
        )

        return ActionResult(
            action_type="quarantine_email",
            success=True,
            action_id=action_id,
            target=message_id,
            message=f"Email {message_id} quarantined. Reason: {reason}",
        )

    async def _action_block_sender(
        self,
        sender: str,
        block_type: Literal["email", "domain"],
        risk_factors: list[str],
    ) -> ActionResult:
        """Execute sender blocking action.

        Args:
            sender: Sender email address.
            block_type: Type of block (email or domain).
            risk_factors: List of detected risk factors.

        Returns:
            ActionResult for the block action.
        """
        reason = "; ".join(risk_factors[:3]) if risk_factors else "Phishing indicators detected"

        if self.dry_run:
            logger.info(
                "dry_run_block_sender",
                sender=sender,
                block_type=block_type,
                reason=reason,
            )
            return ActionResult(
                action_type=f"block_sender_{block_type}",
                success=True,
                action_id=f"dry-run-{uuid.uuid4().hex[:8]}",
                target=sender,
                message=f"[DRY RUN] Would block {block_type}: {sender}",
            )

        # Mock action execution
        action_id = f"bs-{uuid.uuid4().hex[:12]}"

        logger.info(
            "block_sender_executed",
            action_id=action_id,
            sender=sender,
            block_type=block_type,
            reason=reason,
        )

        return ActionResult(
            action_type=f"block_sender_{block_type}",
            success=True,
            action_id=action_id,
            target=sender,
            message=f"Blocked {block_type}: {sender}. Reason: {reason}",
        )

    async def _action_notify_user(
        self,
        recipient: str,
        email_subject: str,
        notification_type: str,
    ) -> ActionResult:
        """Execute user notification action.

        Args:
            recipient: Email address to notify.
            email_subject: Subject of the suspicious email.
            notification_type: Type of notification.

        Returns:
            ActionResult for the notification action.
        """
        if self.dry_run:
            logger.info(
                "dry_run_notify_user",
                recipient=recipient,
                notification_type=notification_type,
            )
            return ActionResult(
                action_type="notify_user",
                success=True,
                action_id=f"dry-run-{uuid.uuid4().hex[:8]}",
                target=recipient,
                message=f"[DRY RUN] Would notify user {recipient}",
            )

        # Mock action execution
        notification_id = f"notif-{uuid.uuid4().hex[:12]}"

        logger.info(
            "notify_user_executed",
            notification_id=notification_id,
            recipient=recipient,
            notification_type=notification_type,
            email_subject=email_subject,
        )

        return ActionResult(
            action_type="notify_user",
            success=True,
            action_id=notification_id,
            target=recipient,
            message=f"User {recipient} notified about suspicious email",
        )

    async def _action_create_ticket(
        self,
        email_analysis: EmailAnalysis,
        phishing_indicators: PhishingIndicators,
        confidence: float,
    ) -> ActionResult:
        """Execute security ticket creation action.

        Args:
            email_analysis: Parsed email analysis.
            phishing_indicators: Detected phishing indicators.
            confidence: Decision confidence.

        Returns:
            ActionResult for the ticket creation action.
        """
        severity = "high" if phishing_indicators.overall_risk_score >= 70 else "medium"
        title = f"Phishing Review Required: {email_analysis.subject[:50]}"

        if self.dry_run:
            logger.info(
                "dry_run_create_ticket",
                title=title,
                severity=severity,
            )
            return ActionResult(
                action_type="create_security_ticket",
                success=True,
                action_id=f"dry-run-{uuid.uuid4().hex[:8]}",
                target=None,
                message=f"[DRY RUN] Would create {severity} severity ticket",
            )

        # Mock action execution
        ticket_id = f"SEC-{uuid.uuid4().hex[:8].upper()}"

        logger.info(
            "create_security_ticket_executed",
            ticket_id=ticket_id,
            title=title,
            severity=severity,
            confidence=confidence,
        )

        return ActionResult(
            action_type="create_security_ticket",
            success=True,
            action_id=ticket_id,
            target=None,
            message=f"Security ticket {ticket_id} created for manual review",
        )

    def _build_summary(
        self,
        decision: TriageDecision,
        confidence: float,
        risk_score: int,
        phishing_indicators: PhishingIndicators,
        sender_reputation: SenderReputationResult,
        url_checks: list[URLCheckResult],
        actions_taken: list[ActionResult],
    ) -> str:
        """Build a human-readable analysis summary.

        Args:
            decision: The triage decision.
            confidence: Decision confidence.
            risk_score: Adjusted risk score.
            phishing_indicators: Detected phishing indicators.
            sender_reputation: Sender reputation result.
            url_checks: URL check results.
            actions_taken: List of executed actions.

        Returns:
            Human-readable summary string.
        """
        summary_parts = []

        # Decision summary
        decision_map = {
            TriageDecision.QUARANTINE: "Email quarantined due to high phishing risk",
            TriageDecision.BLOCK_SENDER: "Email quarantined and sender blocked (phishing)",
            TriageDecision.NEEDS_REVIEW: "Email flagged for manual review",
            TriageDecision.BENIGN: "Email classified as benign",
        }
        summary_parts.append(f"Decision: {decision_map.get(decision, decision.value)}")
        summary_parts.append(f"Risk Score: {risk_score}/100 (Confidence: {confidence:.0%})")

        # Key findings
        findings = []

        if phishing_indicators.typosquat_domains:
            domains = [m.suspicious_domain for m in phishing_indicators.typosquat_domains[:2]]
            findings.append(f"Typosquatting detected: {', '.join(domains)}")

        if phishing_indicators.credential_request_detected:
            findings.append("Credential request detected")

        if phishing_indicators.urgency_phrases:
            phrases = phishing_indicators.urgency_phrases[:2]
            findings.append(f"Urgency language: {', '.join(phrases)}")

        if phishing_indicators.url_text_mismatch:
            findings.append("URL/text mismatch detected")

        if sender_reputation.risk_level == "high":
            findings.append(f"Sender reputation: High risk (score: {sender_reputation.score})")

        malicious_urls = [u for u in url_checks if u.verdict == "malicious"]
        if malicious_urls:
            findings.append(f"Malicious URLs detected: {len(malicious_urls)}")

        if findings:
            summary_parts.append("Key Findings: " + "; ".join(findings))

        # Actions taken
        if actions_taken:
            successful_actions = [a for a in actions_taken if a.success]
            if successful_actions:
                action_types = list(set(a.action_type for a in successful_actions))
                summary_parts.append(f"Actions Taken: {', '.join(action_types)}")

        return " | ".join(summary_parts)

    def _email_analysis_to_dict(self, analysis: EmailAnalysis) -> dict[str, Any]:
        """Convert EmailAnalysis to dictionary.

        Args:
            analysis: EmailAnalysis object.

        Returns:
            Dictionary representation.
        """
        return {
            "message_id": analysis.message_id,
            "subject": analysis.subject,
            "sender": analysis.sender,
            "sender_display_name": analysis.sender_display_name,
            "reply_to": analysis.reply_to,
            "recipients": analysis.recipients,
            "cc": analysis.cc,
            "url_count": len(analysis.urls),
            "attachment_count": len(analysis.attachments),
            "authentication": {
                "spf": analysis.authentication.spf,
                "dkim": analysis.authentication.dkim,
                "dmarc": analysis.authentication.dmarc,
            },
        }

    def _phishing_indicators_to_dict(self, indicators: PhishingIndicators) -> dict[str, Any]:
        """Convert PhishingIndicators to dictionary.

        Args:
            indicators: PhishingIndicators object.

        Returns:
            Dictionary representation.
        """
        return {
            "overall_risk_score": indicators.overall_risk_score,
            "typosquat_domains": [
                {
                    "suspicious_domain": m.suspicious_domain,
                    "similar_to": m.similar_to,
                    "similarity_score": m.similarity_score,
                    "technique": m.technique,
                }
                for m in indicators.typosquat_domains
            ],
            "urgency_phrases": indicators.urgency_phrases,
            "credential_request_detected": indicators.credential_request_detected,
            "suspicious_urls": indicators.suspicious_urls,
            "url_text_mismatch": indicators.url_text_mismatch,
            "sender_domain_mismatch": indicators.sender_domain_mismatch,
            "attachment_risk_level": indicators.attachment_risk_level,
            "risk_factors": indicators.risk_factors,
        }

    # =========================================================================
    # AI-Integrated Triage Method
    # =========================================================================

    async def triage(self, alert: dict[str, Any]) -> TriageResult:
        """Execute the AI-integrated phishing triage workflow.

        This method uses a ReAct agent for AI-powered decision making through
        five stages: PARSE, ANALYZE, ENRICH, DECIDE, and APPROVE.

        Requires agent and tools to be provided during initialization.

        Args:
            alert: Raw email alert data containing:
                - message_id: Unique message identifier
                - subject: Email subject
                - sender or from: Sender address
                - recipients or to: Recipient addresses
                - body_text and/or body_html: Email body content
                - headers: Email headers (optional)
                - attachments: List of attachment info (optional)

        Returns:
            TriageResult with verdict, confidence, actions, and analysis details.

        Raises:
            ValueError: If agent or tools were not provided during initialization.
        """
        if self.agent is None or self.tools is None:
            raise ValueError(
                "AI-integrated triage requires 'agent' and 'tools' to be provided "
                "during initialization. Use run() for rule-based triage."
            )

        start_time = time.time()
        stages_completed: list[str] = []
        email_analysis: EmailAnalysis | None = None
        phishing_indicators: PhishingIndicators | None = None
        enrichment_data: dict[str, Any] = {}
        analysis: Any | None = None  # TriageAnalysis
        proposed_actions: list[dict] = []
        approved_actions: list[dict] = []
        rejected_actions: list[dict] = []
        error: str | None = None

        logger.info(
            "phishing_ai_triage_started",
            message_id=alert.get("message_id", "unknown"),
        )

        # Stage 1: PARSE - Parse email from alert
        try:
            email_analysis = parse_email_alert(alert)
            stages_completed.append(STAGE_PARSE)
            self._notify_ai_stage_complete(
                STAGE_PARSE,
                {
                    "sender": email_analysis.sender,
                    "subject": email_analysis.subject,
                    "url_count": len(email_analysis.urls),
                    "attachment_count": len(email_analysis.attachments),
                },
            )
            logger.debug(
                "ai_stage_parse_complete",
                sender=email_analysis.sender,
                subject=email_analysis.subject,
            )
        except Exception as e:
            logger.error("ai_stage_parse_failed", error=str(e))
            error = f"PARSE stage failed: {str(e)}"
            # Continue with partial results

        # Stage 2: ANALYZE - Run phishing indicator analysis
        try:
            if email_analysis:
                phishing_data = self._build_ai_phishing_data(alert, email_analysis)
                phishing_indicators = analyze_phishing_indicators(phishing_data)
                stages_completed.append(STAGE_ANALYZE)
                self._notify_ai_stage_complete(
                    STAGE_ANALYZE,
                    {
                        "risk_score": phishing_indicators.overall_risk_score,
                        "typosquat_count": len(phishing_indicators.typosquat_domains),
                        "urgency_phrases": len(phishing_indicators.urgency_phrases),
                        "credential_request": phishing_indicators.credential_request_detected,
                    },
                )
                logger.debug(
                    "ai_stage_analyze_complete",
                    risk_score=phishing_indicators.overall_risk_score,
                )
        except Exception as e:
            logger.error("ai_stage_analyze_failed", error=str(e))
            if error is None:
                error = f"ANALYZE stage failed: {str(e)}"

        # Stage 3: ENRICH - Lookup URLs and sender domain via tools
        try:
            enrichment_data = await self._run_ai_enrichment(email_analysis)
            stages_completed.append(STAGE_ENRICH)
            self._notify_ai_stage_complete(STAGE_ENRICH, enrichment_data)
            logger.debug(
                "ai_stage_enrich_complete",
                url_lookups=len(enrichment_data.get("url_results", [])),
                domain_lookup=enrichment_data.get("domain_result") is not None,
            )
        except Exception as e:
            logger.error("ai_stage_enrich_failed", error=str(e))
            if error is None:
                error = f"ENRICH stage failed: {str(e)}"

        # Stage 4: DECIDE - Run ReAct agent with phishing prompt
        agent_result: Any | None = None
        try:
            agent_result = await self._run_ai_agent(
                alert, email_analysis, phishing_indicators, enrichment_data
            )
            if agent_result.success and agent_result.analysis:
                analysis = agent_result.analysis
                proposed_actions = self._extract_ai_proposed_actions(analysis)
            stages_completed.append(STAGE_DECIDE)
            self._notify_ai_stage_complete(
                STAGE_DECIDE,
                {
                    "success": agent_result.success,
                    "verdict": analysis.verdict if analysis else None,
                    "confidence": analysis.confidence if analysis else None,
                    "proposed_actions_count": len(proposed_actions),
                },
            )
            logger.debug(
                "ai_stage_decide_complete",
                success=agent_result.success,
                verdict=analysis.verdict if analysis else None,
            )
        except Exception as e:
            logger.error("ai_stage_decide_failed", error=str(e))
            if error is None:
                error = f"DECIDE stage failed: {str(e)}"

        # Stage 5: APPROVE - Check each proposed action against policy
        try:
            approved_actions, rejected_actions = self._check_ai_actions_against_policy(
                proposed_actions,
                analysis.confidence if analysis else 0,
            )
            stages_completed.append(STAGE_APPROVE)
            self._notify_ai_stage_complete(
                STAGE_APPROVE,
                {
                    "approved_count": len(approved_actions),
                    "rejected_count": len(rejected_actions),
                },
            )
            logger.debug(
                "ai_stage_approve_complete",
                approved=len(approved_actions),
                rejected=len(rejected_actions),
            )
        except Exception as e:
            logger.error("ai_stage_approve_failed", error=str(e))
            if error is None:
                error = f"APPROVE stage failed: {str(e)}"

        # Build final result
        execution_time = time.time() - start_time

        # Determine verdict from analysis or fallback to phishing indicators
        verdict, confidence = self._determine_ai_verdict(
            analysis, phishing_indicators, enrichment_data
        )

        logger.info(
            "phishing_ai_triage_completed",
            verdict=verdict,
            confidence=confidence,
            stages_completed=stages_completed,
            execution_time_seconds=execution_time,
        )

        return TriageResult(
            verdict=verdict,
            confidence=confidence,
            analysis=analysis,
            email_analysis=email_analysis,
            phishing_indicators=phishing_indicators,
            proposed_actions=proposed_actions,
            approved_actions=approved_actions,
            rejected_actions=rejected_actions,
            execution_time_seconds=execution_time,
            stages_completed=stages_completed,
            error=error,
        )

    def _notify_ai_stage_complete(self, stage_name: str, data: Any) -> None:
        """Notify callback of AI stage completion if registered."""
        if self._on_stage_complete:
            try:
                self._on_stage_complete(stage_name, data)
            except Exception as e:
                logger.warning(
                    "ai_stage_complete_callback_error",
                    stage=stage_name,
                    error=str(e),
                )

    def _build_ai_phishing_data(
        self, alert: dict[str, Any], email_analysis: EmailAnalysis
    ) -> dict[str, Any]:
        """Build the data dict expected by analyze_phishing_indicators for AI mode."""
        return {
            "subject": email_analysis.subject,
            "body": email_analysis.body_text or email_analysis.body_html or "",
            "sender_email": email_analysis.sender,
            "sender_display_name": email_analysis.sender_display_name or "",
            "reply_to": email_analysis.reply_to or "",
            "urls": [url.url for url in email_analysis.urls],
            "url_display_texts": [
                {"url": url.url, "display_text": url.display_text or ""}
                for url in email_analysis.urls
                if url.display_text
            ],
            "attachments": [att.filename for att in email_analysis.attachments],
        }

    async def _run_ai_enrichment(self, email_analysis: EmailAnalysis | None) -> dict[str, Any]:
        """Run URL and domain lookups via tools for AI mode.

        Args:
            email_analysis: Parsed email analysis

        Returns:
            Dictionary with 'url_results' and 'domain_result' keys
        """
        results: dict[str, Any] = {
            "url_results": [],
            "domain_result": None,
        }

        if email_analysis is None:
            return results

        # Lookup sender domain
        if email_analysis.sender and "@" in email_analysis.sender:
            domain = email_analysis.sender.split("@")[-1].lower().strip()
            if domain:
                try:
                    domain_result = await self.tools.execute("lookup_domain", {"domain": domain})
                    results["domain_result"] = {
                        "domain": domain,
                        "result": domain_result,
                    }
                except Exception as e:
                    logger.warning(
                        "ai_domain_lookup_failed",
                        domain=domain,
                        error=str(e),
                    )

        # Lookup URLs (limit to first 5 to avoid excessive calls)
        for url_info in email_analysis.urls[:5]:
            try:
                domain = url_info.domain
                if domain:
                    url_result = await self.tools.execute("lookup_domain", {"domain": domain})
                    results["url_results"].append(
                        {
                            "url": url_info.url,
                            "domain": domain,
                            "result": url_result,
                        }
                    )
            except Exception as e:
                logger.warning(
                    "ai_url_lookup_failed",
                    url=url_info.url,
                    error=str(e),
                )

        return results

    async def _run_ai_agent(
        self,
        alert: dict[str, Any],
        email_analysis: EmailAnalysis | None,
        phishing_indicators: PhishingIndicators | None,
        enrichment_data: dict[str, Any],
    ) -> Any:
        """Run the ReAct agent for phishing verdict.

        Args:
            alert: Original alert data
            email_analysis: Parsed email analysis
            phishing_indicators: Detected phishing indicators
            enrichment_data: URL and domain lookup results

        Returns:
            AgentResult from the agent
        """
        # Import here to avoid circular imports
        from tw_ai.agents.react import TriageRequest

        # Build context for the agent
        context = self._build_ai_agent_context(email_analysis, phishing_indicators, enrichment_data)

        # Create triage request
        request = TriageRequest(
            alert_type="phishing",
            alert_data=alert,
            context=context,
            priority=(
                "high"
                if (phishing_indicators and phishing_indicators.overall_risk_score >= 70)
                else "medium"
            ),
        )

        # Run the agent
        return await self.agent.run(request)

    def _build_ai_agent_context(
        self,
        email_analysis: EmailAnalysis | None,
        phishing_indicators: PhishingIndicators | None,
        enrichment_data: dict[str, Any],
    ) -> dict[str, Any]:
        """Build context dict for the AI agent."""
        context: dict[str, Any] = {}

        if email_analysis:
            context["email"] = {
                "sender": email_analysis.sender,
                "sender_display_name": email_analysis.sender_display_name,
                "subject": email_analysis.subject,
                "recipients": email_analysis.recipients,
                "url_count": len(email_analysis.urls),
                "attachment_count": len(email_analysis.attachments),
                "authentication": {
                    "spf": email_analysis.authentication.spf,
                    "dkim": email_analysis.authentication.dkim,
                    "dmarc": email_analysis.authentication.dmarc,
                },
            }

        if phishing_indicators:
            context["phishing_analysis"] = {
                "risk_score": phishing_indicators.overall_risk_score,
                "typosquat_domains": [
                    {
                        "domain": m.suspicious_domain,
                        "similar_to": m.similar_to,
                        "technique": m.technique,
                    }
                    for m in phishing_indicators.typosquat_domains
                ],
                "urgency_phrases": phishing_indicators.urgency_phrases[:5],
                "credential_request_detected": phishing_indicators.credential_request_detected,
                "url_text_mismatch": phishing_indicators.url_text_mismatch,
                "sender_domain_mismatch": phishing_indicators.sender_domain_mismatch,
                "attachment_risk_level": phishing_indicators.attachment_risk_level,
                "risk_factors": phishing_indicators.risk_factors,
            }

        if enrichment_data:
            context["enrichment"] = enrichment_data

        return context

    def _extract_ai_proposed_actions(self, analysis: Any) -> list[dict]:
        """Extract proposed actions from AI agent analysis.

        Args:
            analysis: TriageAnalysis from agent

        Returns:
            List of action dictionaries
        """
        actions = []
        for rec in analysis.recommended_actions:
            actions.append(
                {
                    "action": rec.action,
                    "priority": rec.priority,
                    "reason": rec.reason,
                    "requires_approval": rec.requires_approval,
                }
            )
        return actions

    def _check_ai_actions_against_policy(
        self,
        proposed_actions: list[dict],
        confidence: float,
    ) -> tuple[list[dict], list[dict]]:
        """Check proposed actions against policy for AI mode.

        Args:
            proposed_actions: List of proposed action dicts
            confidence: Confidence score (0-100)

        Returns:
            Tuple of (approved_actions, rejected_actions)
        """
        approved = []
        rejected = []

        for action in proposed_actions:
            if self.policy_checker:
                try:
                    # Build policy check request
                    check_result = self.policy_checker(
                        {
                            "action_type": action.get("action", ""),
                            "target": "",  # Would need actual target
                            "confidence": confidence / 100.0,  # Convert to 0-1
                            "priority": action.get("priority", "low"),
                        }
                    )

                    decision = check_result.get("decision", "denied")
                    if decision == "allowed":
                        approved.append(
                            {
                                **action,
                                "policy_decision": "allowed",
                            }
                        )
                    elif decision == "requires_approval":
                        approved.append(
                            {
                                **action,
                                "policy_decision": "requires_approval",
                                "approval_reason": check_result.get("reason"),
                            }
                        )
                    else:
                        rejected.append(
                            {
                                **action,
                                "policy_decision": "denied",
                                "rejection_reason": check_result.get("reason"),
                            }
                        )
                except Exception as e:
                    logger.warning(
                        "ai_policy_check_failed",
                        action=action,
                        error=str(e),
                    )
                    # Default to requires approval on error
                    approved.append(
                        {
                            **action,
                            "policy_decision": "requires_approval",
                            "approval_reason": "Policy check failed",
                        }
                    )
            else:
                # No policy checker - default behavior
                if action.get("requires_approval", False):
                    approved.append(
                        {
                            **action,
                            "policy_decision": "requires_approval",
                        }
                    )
                else:
                    approved.append(
                        {
                            **action,
                            "policy_decision": "allowed",
                        }
                    )

        return approved, rejected

    def _determine_ai_verdict(
        self,
        analysis: Any | None,
        phishing_indicators: PhishingIndicators | None,
        enrichment_data: dict[str, Any],
    ) -> tuple[str, float]:
        """Determine the final verdict and confidence for AI mode.

        Uses agent analysis if available, otherwise falls back to
        phishing indicators and enrichment data.

        Args:
            analysis: TriageAnalysis from agent
            phishing_indicators: Detected phishing indicators
            enrichment_data: URL and domain lookup results

        Returns:
            Tuple of (verdict, confidence)
        """
        # If agent provided analysis, use its verdict
        if analysis:
            # Map agent verdicts to our verdict format
            verdict_map = {
                "true_positive": "malicious",
                "false_positive": "benign",
                "suspicious": "suspicious",
                "inconclusive": "inconclusive",
            }
            verdict = verdict_map.get(analysis.verdict, "inconclusive")
            confidence = float(analysis.confidence)
            return verdict, confidence

        # Fallback: use phishing indicators and enrichment
        if phishing_indicators:
            risk_score = phishing_indicators.overall_risk_score

            # Check enrichment for malicious verdicts
            malicious_domains = 0
            if enrichment_data:
                for url_result in enrichment_data.get("url_results", []):
                    result = url_result.get("result", {})
                    if hasattr(result, "data"):
                        result = result.data
                    if isinstance(result, dict) and result.get("verdict") == "malicious":
                        malicious_domains += 1

                domain_result = enrichment_data.get("domain_result", {})
                if domain_result:
                    result = domain_result.get("result", {})
                    if hasattr(result, "data"):
                        result = result.data
                    if isinstance(result, dict) and result.get("verdict") == "malicious":
                        malicious_domains += 1

            # Determine verdict based on risk score and enrichment
            if risk_score >= 80 or malicious_domains >= 2:
                return "malicious", min(90.0, risk_score + 10.0)
            elif risk_score >= 50 or malicious_domains >= 1:
                return "suspicious", min(70.0, risk_score)
            elif risk_score >= 30:
                return "suspicious", min(50.0, risk_score)
            else:
                return "benign", max(60.0, 100.0 - risk_score)

        # Ultimate fallback
        return "inconclusive", 30.0
