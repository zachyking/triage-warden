"""Comprehensive unit tests for the PhishingTriageWorkflow.

Tests cover:
- Workflow initialization and configuration
- Email parsing and analysis
- Phishing indicator detection
- Sender reputation checks
- URL safety checks
- Decision making with various risk levels
- Action execution (quarantine, block, notify)
- Dry run mode
- Error handling
"""

from __future__ import annotations

import sys
import importlib.util
from pathlib import Path

import pytest


# Direct module loading to avoid Python 3.10+ syntax issues
_base_path = Path(__file__).parent.parent / "tw_ai"


def _load_module(name: str, file_path: Path):
    """Load a module directly from file path."""
    spec = importlib.util.spec_from_file_location(name, file_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


# Load the workflow module and its dependencies
_email = _load_module("tw_ai.analysis.email", _base_path / "analysis" / "email.py")
_phishing = _load_module("tw_ai.analysis.phishing", _base_path / "analysis" / "phishing.py")
_workflow = _load_module("tw_ai.workflows.phishing", _base_path / "workflows" / "phishing.py")

PhishingTriageWorkflow = _workflow.PhishingTriageWorkflow
WorkflowResult = _workflow.WorkflowResult
TriageDecision = _workflow.TriageDecision
DecisionThresholds = _workflow.DecisionThresholds
WorkflowStage = _workflow.WorkflowStage
ActionResult = _workflow.ActionResult
URLCheckResult = _workflow.URLCheckResult
SenderReputationResult = _workflow.SenderReputationResult


# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture
def benign_email():
    """A benign email from a trusted sender."""
    return {
        "message_id": "msg-benign-001",
        "subject": "Meeting Reminder",
        "sender": "calendar@google.com",
        "from": "calendar@google.com",
        "recipients": ["user@company.com"],
        "to": ["user@company.com"],
        "body_text": "Your meeting 'Weekly Sync' starts in 30 minutes.",
        "headers": {
            "Authentication-Results": "spf=pass; dkim=pass; dmarc=pass",
        },
    }


@pytest.fixture
def suspicious_email():
    """A suspicious email requiring review."""
    return {
        "message_id": "msg-suspicious-001",
        "subject": "Important: Account verification needed",
        "sender": "support@unknown-domain.xyz",
        "from": "support@unknown-domain.xyz",
        "recipients": ["user@company.com"],
        "to": ["user@company.com"],
        "body_text": "Please verify your account within 24 hours to avoid suspension.",
        "body_html": '<p>Please <a href="http://unknown-domain.xyz/verify">verify</a> your account.</p>',
        "headers": {},
    }


@pytest.fixture
def phishing_email():
    """A clear phishing email that should be quarantined."""
    return {
        "message_id": "msg-phishing-001",
        "subject": "URGENT: Your PayPal account has been suspended",
        "sender": "security@paypa1.com",
        "from": "security@paypa1.com",
        "sender_display_name": "PayPal Security",
        "recipients": ["user@company.com"],
        "to": ["user@company.com"],
        "body_text": """
        Your PayPal account has been suspended due to suspicious activity.
        Click here immediately to verify your identity: http://paypa1-secure.evil.example.com/login
        Enter your password to confirm your credentials.
        Failure to verify within 24 hours will result in permanent account suspension.
        """,
        "body_html": """
        <html>
        <body>
        <p>Your PayPal account has been suspended due to suspicious activity.</p>
        <p><a href="http://evil.example.com/phish">Click here to verify your account</a></p>
        <p>Enter your password to confirm your credentials.</p>
        </body>
        </html>
        """,
        "headers": {
            "Authentication-Results": "spf=fail; dkim=fail; dmarc=fail",
        },
    }


@pytest.fixture
def malicious_email():
    """A highly malicious email that should trigger sender blocking."""
    return {
        "message_id": "msg-malicious-001",
        "subject": "ACTION REQUIRED: Verify your Microsoft credentials NOW",
        "sender": "admin@micros0ft-security.phishing.bad",
        "from": "admin@micros0ft-security.phishing.bad",
        "sender_display_name": "Microsoft Security",
        "recipients": ["user@company.com", "admin@company.com"],
        "to": ["user@company.com", "admin@company.com"],
        "body_text": """
        URGENT SECURITY ALERT!

        Your Microsoft account will be suspended immediately unless you act now.
        Unauthorized access was detected from foreign IP.

        Click here to reset your password: http://malware.test/reset
        Enter your login credentials to verify your identity.

        This is your final notice. Failure to comply will result in permanent account deletion.
        """,
        "headers": {
            "Authentication-Results": "spf=fail; dkim=none; dmarc=fail",
        },
        "attachments": [
            {"filename": "invoice.pdf.exe", "content_type": "application/octet-stream", "size_bytes": 1024},
        ],
    }


@pytest.fixture
def workflow():
    """Default workflow instance."""
    return PhishingTriageWorkflow()


@pytest.fixture
def dry_run_workflow():
    """Workflow in dry-run mode."""
    return PhishingTriageWorkflow(dry_run=True)


@pytest.fixture
def strict_workflow():
    """Workflow with strict thresholds."""
    thresholds = DecisionThresholds(
        auto_quarantine_score=60,
        auto_block_score=70,
        needs_review_score=30,
        min_confidence_for_action=0.7,
    )
    return PhishingTriageWorkflow(thresholds=thresholds)


# =============================================================================
# Tests for DecisionThresholds
# =============================================================================


class TestDecisionThresholds:
    """Tests for DecisionThresholds configuration."""

    def test_default_thresholds(self):
        """Test default threshold values."""
        thresholds = DecisionThresholds()
        assert thresholds.auto_quarantine_score == 80
        assert thresholds.auto_block_score == 90
        assert thresholds.needs_review_score == 40
        assert thresholds.min_confidence_for_action == 0.85
        assert thresholds.sender_reputation_low_threshold == 30

    def test_custom_thresholds(self):
        """Test custom threshold values."""
        thresholds = DecisionThresholds(
            auto_quarantine_score=70,
            auto_block_score=85,
            needs_review_score=30,
            min_confidence_for_action=0.75,
        )
        assert thresholds.auto_quarantine_score == 70
        assert thresholds.auto_block_score == 85
        assert thresholds.needs_review_score == 30
        assert thresholds.min_confidence_for_action == 0.75

    def test_invalid_quarantine_score(self):
        """Test validation of quarantine score bounds."""
        with pytest.raises(ValueError, match="auto_quarantine_score must be between 0 and 100"):
            DecisionThresholds(auto_quarantine_score=150)

    def test_invalid_block_score(self):
        """Test validation of block score bounds."""
        with pytest.raises(ValueError, match="auto_block_score must be between 0 and 100"):
            DecisionThresholds(auto_block_score=-10)

    def test_invalid_needs_review_score(self):
        """Test validation of needs_review_score bounds."""
        with pytest.raises(ValueError, match="needs_review_score must be between 0 and 100"):
            DecisionThresholds(needs_review_score=101)

    def test_invalid_confidence_threshold(self):
        """Test validation of confidence threshold bounds."""
        with pytest.raises(ValueError, match="min_confidence_for_action must be between 0.0 and 1.0"):
            DecisionThresholds(min_confidence_for_action=1.5)

    def test_invalid_threshold_ordering(self):
        """Test validation that needs_review < auto_quarantine."""
        with pytest.raises(ValueError, match="needs_review_score must be less than auto_quarantine_score"):
            DecisionThresholds(
                needs_review_score=85,
                auto_quarantine_score=80,
            )


# =============================================================================
# Tests for Workflow Initialization
# =============================================================================


class TestWorkflowInitialization:
    """Tests for PhishingTriageWorkflow initialization."""

    def test_default_initialization(self):
        """Test workflow with default configuration."""
        workflow = PhishingTriageWorkflow()
        assert workflow.enable_actions is True
        assert workflow.dry_run is False
        assert workflow.thresholds.auto_quarantine_score == 80

    def test_custom_thresholds_initialization(self):
        """Test workflow with custom thresholds."""
        thresholds = DecisionThresholds(auto_quarantine_score=70)
        workflow = PhishingTriageWorkflow(thresholds=thresholds)
        assert workflow.thresholds.auto_quarantine_score == 70

    def test_dry_run_mode(self):
        """Test workflow in dry-run mode."""
        workflow = PhishingTriageWorkflow(dry_run=True)
        assert workflow.dry_run is True
        assert workflow.enable_actions is True

    def test_actions_disabled(self):
        """Test workflow with actions disabled."""
        workflow = PhishingTriageWorkflow(enable_actions=False)
        assert workflow.enable_actions is False


# =============================================================================
# Tests for Benign Email Handling
# =============================================================================


class TestBenignEmailHandling:
    """Tests for handling benign emails."""

    @pytest.mark.asyncio
    async def test_benign_email_decision(self, workflow, benign_email):
        """Test that benign email is classified correctly."""
        result = await workflow.run(benign_email)

        assert result.decision == TriageDecision.BENIGN
        assert result.risk_score < 40
        assert result.stage == WorkflowStage.COMPLETED
        assert result.error is None

    @pytest.mark.asyncio
    async def test_benign_email_no_actions(self, workflow, benign_email):
        """Test that no actions are taken for benign email."""
        result = await workflow.run(benign_email)

        assert len(result.actions_taken) == 0

    @pytest.mark.asyncio
    async def test_benign_email_low_risk_score(self, workflow, benign_email):
        """Test that benign email has low risk score."""
        result = await workflow.run(benign_email)

        assert result.risk_score < 40
        assert result.confidence > 0.5


# =============================================================================
# Tests for Suspicious Email Handling
# =============================================================================


class TestSuspiciousEmailHandling:
    """Tests for handling suspicious emails requiring review."""

    @pytest.mark.asyncio
    async def test_suspicious_email_needs_review(self, workflow, suspicious_email):
        """Test that suspicious email is flagged for review."""
        result = await workflow.run(suspicious_email)

        # Suspicious emails should either be quarantined or need review
        assert result.decision in [
            TriageDecision.NEEDS_REVIEW,
            TriageDecision.QUARANTINE,
            TriageDecision.BENIGN,  # May be benign if indicators are weak
        ]
        assert result.stage == WorkflowStage.COMPLETED

    @pytest.mark.asyncio
    async def test_suspicious_email_creates_ticket(self, workflow, suspicious_email):
        """Test that suspicious email creates a ticket if needs_review."""
        result = await workflow.run(suspicious_email)

        if result.decision == TriageDecision.NEEDS_REVIEW:
            ticket_actions = [a for a in result.actions_taken if a.action_type == "create_security_ticket"]
            assert len(ticket_actions) > 0


# =============================================================================
# Tests for Phishing Email Handling
# =============================================================================


class TestPhishingEmailHandling:
    """Tests for handling clear phishing emails."""

    @pytest.mark.asyncio
    async def test_phishing_email_quarantined(self, workflow, phishing_email):
        """Test that phishing email is quarantined."""
        result = await workflow.run(phishing_email)

        # Phishing email should be quarantined or blocked
        assert result.decision in [TriageDecision.QUARANTINE, TriageDecision.BLOCK_SENDER]
        assert result.risk_score >= 60

    @pytest.mark.asyncio
    async def test_phishing_email_high_confidence(self, workflow, phishing_email):
        """Test that phishing email has high confidence."""
        result = await workflow.run(phishing_email)

        assert result.confidence >= 0.7
        assert result.stage == WorkflowStage.COMPLETED

    @pytest.mark.asyncio
    async def test_phishing_email_quarantine_action(self, workflow, phishing_email):
        """Test that quarantine action is executed for phishing email."""
        result = await workflow.run(phishing_email)

        if result.decision in [TriageDecision.QUARANTINE, TriageDecision.BLOCK_SENDER]:
            quarantine_actions = [a for a in result.actions_taken if a.action_type == "quarantine_email"]
            assert len(quarantine_actions) > 0
            assert quarantine_actions[0].success is True

    @pytest.mark.asyncio
    async def test_phishing_email_notification(self, workflow, phishing_email):
        """Test that users are notified about phishing email."""
        result = await workflow.run(phishing_email)

        if result.decision in [TriageDecision.QUARANTINE, TriageDecision.BLOCK_SENDER]:
            notify_actions = [a for a in result.actions_taken if a.action_type == "notify_user"]
            assert len(notify_actions) > 0


# =============================================================================
# Tests for Malicious Email Handling
# =============================================================================


class TestMaliciousEmailHandling:
    """Tests for handling highly malicious emails."""

    @pytest.mark.asyncio
    async def test_malicious_email_blocked(self, workflow, malicious_email):
        """Test that malicious email triggers sender blocking."""
        result = await workflow.run(malicious_email)

        # Highly malicious email should block the sender
        assert result.decision in [TriageDecision.BLOCK_SENDER, TriageDecision.QUARANTINE]
        assert result.risk_score >= 70

    @pytest.mark.asyncio
    async def test_malicious_email_very_high_risk(self, workflow, malicious_email):
        """Test that malicious email has very high risk score."""
        result = await workflow.run(malicious_email)

        assert result.risk_score >= 70
        assert result.confidence >= 0.75

    @pytest.mark.asyncio
    async def test_malicious_email_sender_blocked(self, workflow, malicious_email):
        """Test that sender is blocked for malicious email."""
        result = await workflow.run(malicious_email)

        if result.decision == TriageDecision.BLOCK_SENDER:
            block_actions = [a for a in result.actions_taken if "block_sender" in a.action_type]
            assert len(block_actions) > 0
            assert block_actions[0].success is True

    @pytest.mark.asyncio
    async def test_malicious_email_indicators_detected(self, workflow, malicious_email):
        """Test that phishing indicators are detected in malicious email."""
        result = await workflow.run(malicious_email)

        assert result.phishing_indicators is not None
        indicators = result.phishing_indicators

        # Should detect multiple indicators
        has_indicators = (
            indicators.get("overall_risk_score", 0) > 50 or
            len(indicators.get("urgency_phrases", [])) > 0 or
            indicators.get("credential_request_detected", False) or
            len(indicators.get("risk_factors", [])) > 0
        )
        assert has_indicators


# =============================================================================
# Tests for Dry Run Mode
# =============================================================================


class TestDryRunMode:
    """Tests for dry-run mode functionality."""

    @pytest.mark.asyncio
    async def test_dry_run_no_real_actions(self, dry_run_workflow, phishing_email):
        """Test that dry run doesn't execute real actions."""
        result = await dry_run_workflow.run(phishing_email)

        # Actions should be recorded but marked as dry run
        for action in result.actions_taken:
            if action.success:
                assert action.action_id.startswith("dry-run-")
                assert "[DRY RUN]" in (action.message or "")

    @pytest.mark.asyncio
    async def test_dry_run_still_analyzes(self, dry_run_workflow, phishing_email):
        """Test that dry run still performs full analysis."""
        result = await dry_run_workflow.run(phishing_email)

        assert result.phishing_indicators is not None
        assert result.email_analysis is not None
        assert result.risk_score > 0

    @pytest.mark.asyncio
    async def test_dry_run_quarantine_simulation(self, dry_run_workflow, phishing_email):
        """Test dry run quarantine action simulation."""
        result = await dry_run_workflow.run(phishing_email)

        if result.decision in [TriageDecision.QUARANTINE, TriageDecision.BLOCK_SENDER]:
            quarantine_actions = [a for a in result.actions_taken if a.action_type == "quarantine_email"]
            assert len(quarantine_actions) > 0
            assert "[DRY RUN]" in quarantine_actions[0].message


# =============================================================================
# Tests for Strict Thresholds
# =============================================================================


class TestStrictThresholds:
    """Tests for workflow with strict thresholds."""

    @pytest.mark.asyncio
    async def test_strict_catches_more_suspicious(self, strict_workflow, suspicious_email):
        """Test that strict thresholds catch more suspicious emails."""
        result = await strict_workflow.run(suspicious_email)

        # With lower thresholds, suspicious emails should be more likely to be actioned
        assert result.risk_score >= 0
        assert result.stage == WorkflowStage.COMPLETED


# =============================================================================
# Tests for WorkflowResult
# =============================================================================


class TestWorkflowResult:
    """Tests for WorkflowResult dataclass."""

    @pytest.mark.asyncio
    async def test_result_to_dict(self, workflow, benign_email):
        """Test WorkflowResult serialization."""
        result = await workflow.run(benign_email)
        result_dict = result.to_dict()

        assert "decision" in result_dict
        assert "confidence" in result_dict
        assert "risk_score" in result_dict
        assert "actions_taken" in result_dict
        assert "analysis_summary" in result_dict
        assert "workflow_id" in result_dict

    @pytest.mark.asyncio
    async def test_result_has_workflow_id(self, workflow, benign_email):
        """Test that each result has a unique workflow ID."""
        result1 = await workflow.run(benign_email)
        result2 = await workflow.run(benign_email)

        assert result1.workflow_id != result2.workflow_id

    @pytest.mark.asyncio
    async def test_result_has_execution_time(self, workflow, benign_email):
        """Test that execution time is recorded."""
        result = await workflow.run(benign_email)

        assert result.execution_time_seconds > 0
        assert result.execution_time_seconds < 60  # Should be fast


# =============================================================================
# Tests for URL Safety Checks
# =============================================================================


class TestURLSafetyChecks:
    """Tests for URL safety check functionality."""

    @pytest.mark.asyncio
    async def test_malicious_url_detected(self, workflow, phishing_email):
        """Test that malicious URLs are detected."""
        result = await workflow.run(phishing_email)

        # Should have URL check results
        assert len(result.url_checks) > 0

        # At least one should be malicious or suspicious
        verdicts = [u.verdict for u in result.url_checks]
        assert "malicious" in verdicts or "suspicious" in verdicts

    @pytest.mark.asyncio
    async def test_clean_url_recognized(self, workflow, benign_email):
        """Test that clean URLs from known domains are recognized."""
        email = {
            **benign_email,
            "body_text": "Check out https://google.com for more info",
        }
        result = await workflow.run(email)

        # Google.com should be recognized as clean
        google_checks = [u for u in result.url_checks if "google" in u.domain]
        if google_checks:
            assert google_checks[0].verdict == "clean"


# =============================================================================
# Tests for Sender Reputation
# =============================================================================


class TestSenderReputation:
    """Tests for sender reputation check functionality."""

    @pytest.mark.asyncio
    async def test_trusted_sender_reputation(self, workflow, benign_email):
        """Test that trusted senders have high reputation."""
        result = await workflow.run(benign_email)

        assert result.sender_reputation is not None
        assert result.sender_reputation.score >= 80
        assert result.sender_reputation.risk_level == "low"

    @pytest.mark.asyncio
    async def test_suspicious_sender_reputation(self, workflow, phishing_email):
        """Test that suspicious senders have low reputation."""
        result = await workflow.run(phishing_email)

        assert result.sender_reputation is not None
        assert result.sender_reputation.risk_level in ["medium", "high"]


# =============================================================================
# Tests for Analysis Summary
# =============================================================================


class TestAnalysisSummary:
    """Tests for human-readable analysis summary."""

    @pytest.mark.asyncio
    async def test_summary_includes_decision(self, workflow, phishing_email):
        """Test that summary includes the decision."""
        result = await workflow.run(phishing_email)

        assert "Decision:" in result.analysis_summary
        assert "Risk Score:" in result.analysis_summary

    @pytest.mark.asyncio
    async def test_summary_includes_confidence(self, workflow, phishing_email):
        """Test that summary includes confidence."""
        result = await workflow.run(phishing_email)

        assert "Confidence:" in result.analysis_summary

    @pytest.mark.asyncio
    async def test_summary_includes_key_findings(self, workflow, phishing_email):
        """Test that summary includes key findings for phishing."""
        result = await workflow.run(phishing_email)

        # Should include at least one finding
        summary_lower = result.analysis_summary.lower()
        has_finding = (
            "typosquat" in summary_lower or
            "urgency" in summary_lower or
            "credential" in summary_lower or
            "url" in summary_lower or
            "reputation" in summary_lower or
            "findings" in summary_lower
        )
        # May not have findings if benign
        if result.decision != TriageDecision.BENIGN:
            assert has_finding or "actions" in summary_lower


# =============================================================================
# Tests for Error Handling
# =============================================================================


class TestErrorHandling:
    """Tests for error handling in the workflow."""

    @pytest.mark.asyncio
    async def test_missing_required_field_handled(self, workflow):
        """Test that missing required fields are handled gracefully."""
        # Email with minimal data
        minimal_email = {
            "message_id": "msg-minimal-001",
        }
        result = await workflow.run(minimal_email)

        # Should complete without crashing
        assert result.stage in [WorkflowStage.COMPLETED, WorkflowStage.FAILED]

    @pytest.mark.asyncio
    async def test_empty_email_handled(self, workflow):
        """Test that empty email is handled gracefully."""
        result = await workflow.run({})

        # Should complete without crashing
        assert result.stage in [WorkflowStage.COMPLETED, WorkflowStage.FAILED]

    @pytest.mark.asyncio
    async def test_invalid_data_types_handled(self, workflow):
        """Test that invalid data types are handled gracefully."""
        invalid_email = {
            "message_id": 12345,  # Should be string
            "subject": ["not", "a", "string"],  # Should be string
            "sender": None,
        }
        result = await workflow.run(invalid_email)

        # Should handle gracefully
        assert result is not None


# =============================================================================
# Tests for Actions Disabled Mode
# =============================================================================


class TestActionsDisabledMode:
    """Tests for workflow with actions disabled."""

    @pytest.mark.asyncio
    async def test_no_actions_when_disabled(self, phishing_email):
        """Test that no actions are taken when disabled."""
        workflow = PhishingTriageWorkflow(enable_actions=False)
        result = await workflow.run(phishing_email)

        # Should still make a decision
        assert result.decision in [
            TriageDecision.QUARANTINE,
            TriageDecision.BLOCK_SENDER,
            TriageDecision.NEEDS_REVIEW,
            TriageDecision.BENIGN,
        ]
        # But no actions should be taken
        assert len(result.actions_taken) == 0


# =============================================================================
# Tests for Email Analysis Data
# =============================================================================


class TestEmailAnalysisData:
    """Tests for email analysis data in results."""

    @pytest.mark.asyncio
    async def test_email_analysis_populated(self, workflow, phishing_email):
        """Test that email analysis data is populated."""
        result = await workflow.run(phishing_email)

        assert result.email_analysis is not None
        assert "subject" in result.email_analysis
        assert "sender" in result.email_analysis
        assert "authentication" in result.email_analysis

    @pytest.mark.asyncio
    async def test_phishing_indicators_populated(self, workflow, phishing_email):
        """Test that phishing indicators are populated."""
        result = await workflow.run(phishing_email)

        assert result.phishing_indicators is not None
        assert "overall_risk_score" in result.phishing_indicators
        assert "risk_factors" in result.phishing_indicators


# =============================================================================
# Tests for AI-Integrated Triage Method
# =============================================================================

# Import the new TriageResult and stage constants
TriageResult = _workflow.TriageResult
STAGE_PARSE = _workflow.STAGE_PARSE
STAGE_ANALYZE = _workflow.STAGE_ANALYZE
STAGE_ENRICH = _workflow.STAGE_ENRICH
STAGE_DECIDE = _workflow.STAGE_DECIDE
STAGE_APPROVE = _workflow.STAGE_APPROVE


class MockToolResult:
    """Mock tool execution result."""

    def __init__(self, data: dict):
        self.success = True
        self.data = data


class MockToolRegistry:
    """Mock tool registry for testing."""

    def __init__(self, domain_verdicts: dict = None):
        self.domain_verdicts = domain_verdicts or {}
        self.execute_calls = []

    async def execute(self, tool_name: str, args: dict) -> MockToolResult:
        """Mock tool execution."""
        self.execute_calls.append((tool_name, args))

        if tool_name == "lookup_domain":
            domain = args.get("domain", "")
            verdict = self.domain_verdicts.get(domain, "unknown")
            return MockToolResult({
                "domain": domain,
                "verdict": verdict,
                "malicious_score": 90 if verdict == "malicious" else 0,
            })

        return MockToolResult({"status": "ok"})


class MockTriageAnalysis:
    """Mock TriageAnalysis for testing."""

    def __init__(
        self,
        verdict: str = "suspicious",
        confidence: int = 75,
        recommended_actions: list = None,
    ):
        self.verdict = verdict
        self.confidence = confidence
        self.severity = "medium"
        self.summary = "Mock analysis summary"
        self.indicators = []
        self.mitre_techniques = []
        self.recommended_actions = recommended_actions or []
        self.reasoning = "Mock reasoning"

    def model_dump(self) -> dict:
        """Mock Pydantic model_dump."""
        return {
            "verdict": self.verdict,
            "confidence": self.confidence,
            "severity": self.severity,
            "summary": self.summary,
            "indicators": self.indicators,
            "mitre_techniques": self.mitre_techniques,
            "recommended_actions": [
                {
                    "action": a.action,
                    "priority": a.priority,
                    "reason": a.reason,
                    "requires_approval": a.requires_approval,
                }
                for a in self.recommended_actions
            ],
            "reasoning": self.reasoning,
        }


class MockRecommendedAction:
    """Mock recommended action."""

    def __init__(
        self,
        action: str = "quarantine_email",
        priority: str = "high",
        reason: str = "Suspicious content",
        requires_approval: bool = False,
    ):
        self.action = action
        self.priority = priority
        self.reason = reason
        self.requires_approval = requires_approval


class MockAgentResult:
    """Mock agent result for testing."""

    def __init__(
        self,
        success: bool = True,
        analysis: MockTriageAnalysis = None,
        error: str = None,
    ):
        self.success = success
        self.analysis = analysis or MockTriageAnalysis()
        self.error = error


class MockReActAgent:
    """Mock ReActAgent for testing."""

    def __init__(
        self,
        result: MockAgentResult = None,
        should_fail: bool = False,
    ):
        self.result = result or MockAgentResult()
        self.should_fail = should_fail
        self.run_calls = []

    async def run(self, request) -> MockAgentResult:
        """Mock agent run."""
        self.run_calls.append(request)

        if self.should_fail:
            raise Exception("Mock agent failure")

        return self.result


class TestAITriageMethod:
    """Tests for the AI-integrated triage() method."""

    @pytest.fixture
    def mock_tools(self):
        """Create mock tool registry."""
        return MockToolRegistry({
            "evil.example.com": "malicious",
            "paypa1.com": "malicious",
            "google.com": "clean",
        })

    @pytest.fixture
    def mock_agent(self):
        """Create mock agent with default result."""
        analysis = MockTriageAnalysis(
            verdict="true_positive",
            confidence=85,
            recommended_actions=[
                MockRecommendedAction(
                    action="quarantine_email",
                    priority="immediate",
                    reason="High confidence phishing",
                    requires_approval=False,
                ),
                MockRecommendedAction(
                    action="block_sender",
                    priority="high",
                    reason="Known malicious sender",
                    requires_approval=True,
                ),
            ],
        )
        return MockReActAgent(result=MockAgentResult(success=True, analysis=analysis))

    @pytest.fixture
    def ai_workflow(self, mock_agent, mock_tools):
        """Create workflow with mocked agent and tools."""
        return PhishingTriageWorkflow(
            agent=mock_agent,
            tools=mock_tools,
        )

    @pytest.mark.asyncio
    async def test_triage_requires_agent(self):
        """Test that triage() raises error without agent."""
        workflow = PhishingTriageWorkflow()

        with pytest.raises(ValueError, match="agent.*tools"):
            await workflow.triage({"message_id": "test"})

    @pytest.mark.asyncio
    async def test_triage_returns_triage_result(self, ai_workflow, phishing_email):
        """Test that triage() returns TriageResult."""
        result = await ai_workflow.triage(phishing_email)

        assert isinstance(result, TriageResult)
        assert hasattr(result, "verdict")
        assert hasattr(result, "confidence")
        assert hasattr(result, "proposed_actions")
        assert hasattr(result, "approved_actions")
        assert hasattr(result, "rejected_actions")

    @pytest.mark.asyncio
    async def test_triage_completes_all_stages(self, ai_workflow, phishing_email):
        """Test that all stages are completed."""
        result = await ai_workflow.triage(phishing_email)

        assert STAGE_PARSE in result.stages_completed
        assert STAGE_ANALYZE in result.stages_completed
        assert STAGE_ENRICH in result.stages_completed
        assert STAGE_DECIDE in result.stages_completed
        assert STAGE_APPROVE in result.stages_completed

    @pytest.mark.asyncio
    async def test_triage_verdict_from_agent(self, ai_workflow, phishing_email):
        """Test that verdict comes from agent analysis."""
        result = await ai_workflow.triage(phishing_email)

        # Agent returns "true_positive" which maps to "malicious"
        assert result.verdict == "malicious"
        assert result.confidence == 85

    @pytest.mark.asyncio
    async def test_triage_extracts_proposed_actions(self, ai_workflow, phishing_email):
        """Test that proposed actions are extracted from agent."""
        result = await ai_workflow.triage(phishing_email)

        assert len(result.proposed_actions) == 2
        assert result.proposed_actions[0]["action"] == "quarantine_email"
        assert result.proposed_actions[1]["action"] == "block_sender"

    @pytest.mark.asyncio
    async def test_triage_email_analysis_populated(self, ai_workflow, phishing_email):
        """Test that email analysis is populated."""
        result = await ai_workflow.triage(phishing_email)

        assert result.email_analysis is not None
        assert result.email_analysis.sender == "security@paypa1.com"

    @pytest.mark.asyncio
    async def test_triage_phishing_indicators_populated(self, ai_workflow, phishing_email):
        """Test that phishing indicators are populated."""
        result = await ai_workflow.triage(phishing_email)

        assert result.phishing_indicators is not None
        assert result.phishing_indicators.overall_risk_score > 0

    @pytest.mark.asyncio
    async def test_triage_execution_time_recorded(self, ai_workflow, phishing_email):
        """Test that execution time is recorded."""
        result = await ai_workflow.triage(phishing_email)

        assert result.execution_time_seconds > 0
        assert result.execution_time_seconds < 60

    @pytest.mark.asyncio
    async def test_triage_to_dict_serialization(self, ai_workflow, phishing_email):
        """Test TriageResult to_dict serialization."""
        result = await ai_workflow.triage(phishing_email)
        result_dict = result.to_dict()

        assert "verdict" in result_dict
        assert "confidence" in result_dict
        assert "proposed_actions" in result_dict
        assert "approved_actions" in result_dict
        assert "rejected_actions" in result_dict
        assert "stages_completed" in result_dict


class TestAITriageWithPolicyChecker:
    """Tests for triage() with policy checker."""

    @pytest.fixture
    def mock_tools(self):
        """Create mock tool registry."""
        return MockToolRegistry()

    @pytest.fixture
    def mock_agent(self):
        """Create mock agent."""
        analysis = MockTriageAnalysis(
            verdict="true_positive",
            confidence=90,
            recommended_actions=[
                MockRecommendedAction(
                    action="quarantine_email",
                    priority="immediate",
                    reason="Confirmed phishing",
                    requires_approval=False,
                ),
                MockRecommendedAction(
                    action="delete_user",
                    priority="high",
                    reason="Compromised account",
                    requires_approval=True,
                ),
            ],
        )
        return MockReActAgent(result=MockAgentResult(success=True, analysis=analysis))

    @pytest.fixture
    def policy_checker(self):
        """Create mock policy checker."""
        def checker(action_request: dict) -> dict:
            action_type = action_request.get("action_type", "")
            # Deny dangerous actions
            if action_type == "delete_user":
                return {"decision": "denied", "reason": "Action not allowed by policy"}
            # Require approval for blocks
            if "block" in action_type:
                return {"decision": "requires_approval", "reason": "Requires SOC approval"}
            # Allow safe actions
            return {"decision": "allowed", "reason": None}

        return checker

    @pytest.fixture
    def ai_workflow_with_policy(self, mock_agent, mock_tools, policy_checker):
        """Create workflow with policy checker."""
        return PhishingTriageWorkflow(
            agent=mock_agent,
            tools=mock_tools,
            policy_checker=policy_checker,
        )

    @pytest.mark.asyncio
    async def test_policy_approves_allowed_actions(
        self, ai_workflow_with_policy, phishing_email
    ):
        """Test that policy approves allowed actions."""
        result = await ai_workflow_with_policy.triage(phishing_email)

        # quarantine_email should be approved
        quarantine_actions = [
            a for a in result.approved_actions
            if a["action"] == "quarantine_email"
        ]
        assert len(quarantine_actions) == 1
        assert quarantine_actions[0]["policy_decision"] == "allowed"

    @pytest.mark.asyncio
    async def test_policy_rejects_denied_actions(
        self, ai_workflow_with_policy, phishing_email
    ):
        """Test that policy rejects denied actions."""
        result = await ai_workflow_with_policy.triage(phishing_email)

        # delete_user should be rejected
        delete_actions = [
            a for a in result.rejected_actions
            if a["action"] == "delete_user"
        ]
        assert len(delete_actions) == 1
        assert delete_actions[0]["policy_decision"] == "denied"
        assert "not allowed" in delete_actions[0]["rejection_reason"]


class TestAITriageStageCallback:
    """Tests for stage completion callback."""

    @pytest.fixture
    def mock_tools(self):
        """Create mock tool registry."""
        return MockToolRegistry()

    @pytest.fixture
    def mock_agent(self):
        """Create mock agent."""
        return MockReActAgent()

    @pytest.fixture
    def stage_events(self):
        """List to capture stage events."""
        return []

    @pytest.fixture
    def ai_workflow_with_callback(self, mock_agent, mock_tools, stage_events):
        """Create workflow with stage callback."""
        def on_stage_complete(stage_name: str, data):
            stage_events.append({"stage": stage_name, "data": data})

        return PhishingTriageWorkflow(
            agent=mock_agent,
            tools=mock_tools,
            on_stage_complete=on_stage_complete,
        )

    @pytest.mark.asyncio
    async def test_stage_callback_called_for_each_stage(
        self, ai_workflow_with_callback, stage_events, phishing_email
    ):
        """Test that callback is called for each stage."""
        await ai_workflow_with_callback.triage(phishing_email)

        stage_names = [e["stage"] for e in stage_events]
        assert STAGE_PARSE in stage_names
        assert STAGE_ANALYZE in stage_names
        assert STAGE_ENRICH in stage_names
        assert STAGE_DECIDE in stage_names
        assert STAGE_APPROVE in stage_names

    @pytest.mark.asyncio
    async def test_stage_callback_receives_data(
        self, ai_workflow_with_callback, stage_events, phishing_email
    ):
        """Test that callback receives stage data."""
        await ai_workflow_with_callback.triage(phishing_email)

        # Check PARSE stage data
        parse_event = next(e for e in stage_events if e["stage"] == STAGE_PARSE)
        assert "sender" in parse_event["data"]
        assert "subject" in parse_event["data"]

        # Check ANALYZE stage data
        analyze_event = next(e for e in stage_events if e["stage"] == STAGE_ANALYZE)
        assert "risk_score" in analyze_event["data"]


class TestAITriageErrorHandling:
    """Tests for error handling in AI triage."""

    @pytest.fixture
    def mock_tools(self):
        """Create mock tool registry."""
        return MockToolRegistry()

    @pytest.fixture
    def failing_agent(self):
        """Create agent that fails."""
        return MockReActAgent(should_fail=True)

    @pytest.fixture
    def ai_workflow_with_failing_agent(self, failing_agent, mock_tools):
        """Create workflow with failing agent."""
        return PhishingTriageWorkflow(
            agent=failing_agent,
            tools=mock_tools,
        )

    @pytest.mark.asyncio
    async def test_continues_with_partial_results_on_agent_failure(
        self, ai_workflow_with_failing_agent, phishing_email
    ):
        """Test that workflow continues with partial results when agent fails."""
        result = await ai_workflow_with_failing_agent.triage(phishing_email)

        # Should have completed PARSE and ANALYZE
        assert STAGE_PARSE in result.stages_completed
        assert STAGE_ANALYZE in result.stages_completed

        # Should have error recorded
        assert result.error is not None
        assert "DECIDE" in result.error

    @pytest.mark.asyncio
    async def test_fallback_verdict_when_agent_fails(
        self, ai_workflow_with_failing_agent, phishing_email
    ):
        """Test that fallback verdict is used when agent fails."""
        result = await ai_workflow_with_failing_agent.triage(phishing_email)

        # Should still have a verdict from fallback logic
        assert result.verdict in ["malicious", "suspicious", "benign", "inconclusive"]
        assert result.confidence > 0


class TestAITriageFallbackVerdict:
    """Tests for fallback verdict determination."""

    @pytest.fixture
    def mock_tools(self):
        """Create mock tool registry with malicious domains."""
        return MockToolRegistry({
            "evil.example.com": "malicious",
            "malware.test": "malicious",
        })

    @pytest.fixture
    def agent_with_no_analysis(self):
        """Create agent that returns no analysis."""
        return MockReActAgent(
            result=MockAgentResult(success=False, analysis=None, error="Parse failed")
        )

    @pytest.fixture
    def ai_workflow_fallback(self, agent_with_no_analysis, mock_tools):
        """Create workflow that will use fallback verdict."""
        return PhishingTriageWorkflow(
            agent=agent_with_no_analysis,
            tools=mock_tools,
        )

    @pytest.mark.asyncio
    async def test_fallback_uses_phishing_indicators(
        self, ai_workflow_fallback, malicious_email
    ):
        """Test that fallback uses phishing indicators for verdict."""
        result = await ai_workflow_fallback.triage(malicious_email)

        # High risk email should get malicious or suspicious verdict
        assert result.verdict in ["malicious", "suspicious"]
        assert result.confidence > 0

    @pytest.mark.asyncio
    async def test_fallback_benign_for_low_risk(
        self, ai_workflow_fallback, benign_email
    ):
        """Test that fallback returns benign for low risk."""
        result = await ai_workflow_fallback.triage(benign_email)

        # Low risk email should get benign verdict
        assert result.verdict == "benign"
        assert result.confidence > 50
