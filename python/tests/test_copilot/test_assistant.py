"""Tests for the investigation copilot assistant."""

import pytest

from tw_ai.copilot.assistant import (
    COPILOT_SYSTEM_PROMPT,
    CopilotResponse,
    InvestigationCopilot,
)


@pytest.fixture
def copilot() -> InvestigationCopilot:
    return InvestigationCopilot()


@pytest.fixture
def phishing_incident() -> dict:
    return {
        "id": "INC-1001",
        "severity": "high",
        "verdict": "true_positive",
        "summary": "Phishing email targeting user credentials via spoofed login page.",
        "alert_type": "phishing",
        "indicators": [
            {"type": "ip", "value": "10.0.0.1", "verdict": "malicious"},
            {"type": "domain", "value": "evil-phish.com", "verdict": "malicious"},
            {"type": "email", "value": "attacker@evil-phish.com", "verdict": "malicious"},
        ],
        "mitre_techniques": [
            {
                "id": "T1566.001",
                "name": "Spearphishing Attachment",
                "tactic": "Initial Access",
            },
        ],
        "evidence": [
            {"source": "email_gateway", "finding": "suspicious email"},
            {"source": "url_scanner", "finding": "malicious URL"},
        ],
    }


@pytest.fixture
def suspicious_incident() -> dict:
    return {
        "id": "INC-2002",
        "severity": "medium",
        "verdict": "suspicious",
        "summary": "Unusual login activity detected.",
        "alert_type": "suspicious_login",
        "indicators": [],
        "mitre_techniques": [],
    }


class TestCopilotResponse:
    def test_model_creation(self):
        resp = CopilotResponse(
            answer="Test answer",
            sources=["incident_data"],
            suggested_actions=["Block IP"],
            suggested_followups=["What are the IOCs?"],
        )
        assert resp.answer == "Test answer"
        assert len(resp.sources) == 1
        assert len(resp.suggested_actions) == 1

    def test_default_values(self):
        resp = CopilotResponse(answer="test")
        assert resp.sources == []
        assert resp.suggested_actions == []
        assert resp.suggested_followups == []
        assert resp.confidence == 0.8
        assert resp.rag_context_used is False


class TestInvestigationCopilot:
    def test_system_prompt_exists(self):
        assert len(COPILOT_SYSTEM_PROMPT) > 100
        assert "security" in COPILOT_SYSTEM_PROMPT.lower()

    def test_assist_summary_question(
        self, copilot: InvestigationCopilot, phishing_incident: dict
    ):
        response = copilot.assist(phishing_incident, "what happened?")
        assert response.answer
        assert "phishing" in response.answer.lower()
        assert "high" in response.answer.lower()
        assert len(response.sources) > 0

    def test_assist_next_steps_question(
        self, copilot: InvestigationCopilot, phishing_incident: dict
    ):
        response = copilot.assist(phishing_incident, "what should I do next?")
        assert response.answer
        assert len(response.suggested_actions) > 0

    def test_assist_ioc_question(
        self, copilot: InvestigationCopilot, phishing_incident: dict
    ):
        response = copilot.assist(phishing_incident, "show me the IOCs")
        assert response.answer
        assert "10.0.0.1" in response.answer or "indicator" in response.answer.lower()

    def test_assist_mitre_question(
        self, copilot: InvestigationCopilot, phishing_incident: dict
    ):
        response = copilot.assist(phishing_incident, "what MITRE techniques")
        assert response.answer
        assert "T1566" in response.answer or "MITRE" in response.answer

    def test_assist_severity_question(
        self, copilot: InvestigationCopilot, phishing_incident: dict
    ):
        response = copilot.assist(phishing_incident, "how serious is this?")
        assert "high" in response.answer.lower()

    def test_assist_general_question(
        self, copilot: InvestigationCopilot, phishing_incident: dict
    ):
        response = copilot.assist(phishing_incident, "hello")
        assert response.answer
        assert len(response.suggested_followups) > 0

    def test_assist_true_positive_actions(
        self, copilot: InvestigationCopilot, phishing_incident: dict
    ):
        response = copilot.assist(phishing_incident, "recommend actions")
        assert len(response.suggested_actions) > 0
        # Should include high severity actions
        actions_text = " ".join(response.suggested_actions).lower()
        assert any(
            w in actions_text
            for w in ["escalate", "isolate", "block", "collect", "quarantine"]
        )

    def test_assist_suspicious_incident(
        self, copilot: InvestigationCopilot, suspicious_incident: dict
    ):
        response = copilot.assist(suspicious_incident, "what should I do?")
        assert response.answer
        # Should suggest gathering evidence
        actions_text = " ".join(response.suggested_actions).lower()
        assert any(w in actions_text for w in ["evidence", "investigate", "check", "review"])

    def test_assist_with_conversation_context(
        self, copilot: InvestigationCopilot, phishing_incident: dict
    ):
        context = {
            "conversation_history": [
                {"role": "user", "content": "what happened?"},
                {"role": "assistant", "content": "A phishing attack was detected."},
            ]
        }
        response = copilot.assist(phishing_incident, "what should I do?", context=context)
        assert response.answer

    def test_followups_for_summary(
        self, copilot: InvestigationCopilot, phishing_incident: dict
    ):
        response = copilot.assist(phishing_incident, "explain this incident")
        assert len(response.suggested_followups) > 0

    def test_followups_for_indicators(
        self, copilot: InvestigationCopilot, phishing_incident: dict
    ):
        response = copilot.assist(phishing_incident, "show IOCs")
        assert len(response.suggested_followups) > 0

    def test_false_positive_recommendation(self, copilot: InvestigationCopilot):
        incident = {
            "id": "INC-3003",
            "severity": "low",
            "verdict": "false_positive",
            "summary": "Benign activity flagged by rule.",
            "alert_type": "generic",
            "indicators": [],
        }
        response = copilot.assist(incident, "what should I do?")
        actions_text = " ".join(response.suggested_actions).lower()
        assert "false positive" in actions_text or "exception" in actions_text or "tuning" in actions_text

    def test_build_context_with_minimal_data(self, copilot: InvestigationCopilot):
        response = copilot.assist({}, "what happened?")
        assert response.answer  # Should handle gracefully
