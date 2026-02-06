"""Investigation copilot for analyst assistance.

Provides an AI-powered assistant that helps security analysts investigate
incidents by answering questions, suggesting next steps, and retrieving
context from the organizational knowledge base.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict, Field

if TYPE_CHECKING:
    from tw_ai.analysis.rag_analyzer import RAGEnhancedAnalyzer
    from tw_ai.llm.base import LLMProvider

COPILOT_SYSTEM_PROMPT = """You are an expert security analyst assistant integrated into a Security \
Orchestration, Automation, and Response (SOAR) platform called Triage Warden.

Your role is to help analysts investigate security incidents by:
1. Answering questions about the current incident, its indicators, and related context
2. Suggesting investigation steps based on the incident type and evidence
3. Explaining MITRE ATT&CK techniques and their relevance
4. Recommending response actions with appropriate risk context
5. Correlating current findings with historical incident data

Guidelines:
- Be concise and actionable in your responses
- Always cite your sources when referencing specific data
- Flag uncertainty explicitly rather than guessing
- Prioritize safety: never recommend destructive actions without clear justification
- Reference specific indicators (IPs, domains, hashes) from the incident data
- When suggesting actions, note the risk level and whether approval is needed

You have access to:
- Current incident data and indicators
- Similar past incidents from the knowledge base
- MITRE ATT&CK framework mappings
- Organizational playbooks and procedures
"""


class CopilotResponse(BaseModel):
    """Response from the investigation copilot."""

    model_config = ConfigDict(str_strip_whitespace=True)

    answer: str = Field(description="The main answer to the analyst's question")
    sources: list[str] = Field(
        default_factory=list,
        description="Sources cited in the answer",
    )
    suggested_actions: list[str] = Field(
        default_factory=list,
        description="Suggested investigation or response actions",
    )
    suggested_followups: list[str] = Field(
        default_factory=list,
        description="Suggested follow-up questions",
    )
    confidence: float = Field(
        default=0.8,
        ge=0.0,
        le=1.0,
        description="Confidence in the response",
    )
    rag_context_used: bool = Field(
        default=False,
        description="Whether RAG context was used",
    )


class InvestigationCopilot:
    """AI-powered investigation assistant for security analysts.

    Integrates with the RAG system to provide context-aware assistance
    during incident investigation.
    """

    def __init__(
        self,
        llm_provider: LLMProvider | None = None,
        rag_analyzer: RAGEnhancedAnalyzer | None = None,
        system_prompt: str = COPILOT_SYSTEM_PROMPT,
    ) -> None:
        """Initialize the investigation copilot.

        Args:
            llm_provider: LLM provider for generating responses.
            rag_analyzer: RAG analyzer for retrieving context.
            system_prompt: System prompt for the copilot persona.
        """
        self._llm = llm_provider
        self._rag_analyzer = rag_analyzer
        self._system_prompt = system_prompt

    def assist(
        self,
        incident_data: dict[str, Any],
        question: str,
        context: dict[str, Any] | None = None,
    ) -> CopilotResponse:
        """Provide assistance for an investigation question.

        Args:
            incident_data: Current incident data including indicators, severity, etc.
            question: The analyst's question.
            context: Additional context (conversation history, etc.).

        Returns:
            CopilotResponse with answer and suggestions.
        """
        # Build the context string
        incident_context = self._build_context(incident_data)
        conversation_context = ""
        if context and "conversation_history" in context:
            conversation_context = self._format_conversation_history(
                context["conversation_history"]
            )

        # If we have an LLM provider, use it
        if self._llm is not None:
            return self._assist_with_llm(incident_context, question, conversation_context)

        # Otherwise, provide rule-based assistance
        return self._assist_rule_based(incident_data, question)

    def _build_context(self, incident_data: dict[str, Any]) -> str:
        """Build a context string from incident data.

        Args:
            incident_data: The incident data dictionary.

        Returns:
            Formatted context string for the LLM.
        """
        parts: list[str] = ["## Current Incident Context"]

        # Basic incident info
        if "id" in incident_data:
            parts.append(f"Incident ID: {incident_data['id']}")
        if "severity" in incident_data:
            parts.append(f"Severity: {incident_data['severity']}")
        if "verdict" in incident_data:
            parts.append(f"Verdict: {incident_data['verdict']}")
        if "summary" in incident_data:
            parts.append(f"Summary: {incident_data['summary']}")
        if "alert_type" in incident_data:
            parts.append(f"Alert Type: {incident_data['alert_type']}")

        # Indicators
        indicators = incident_data.get("indicators", [])
        if indicators:
            parts.append("\n### Indicators of Compromise")
            for ind in indicators[:10]:  # Limit to 10
                if isinstance(ind, dict):
                    parts.append(
                        f"- [{ind.get('type', 'unknown')}] "
                        f"{ind.get('value', '')} "
                        f"({ind.get('verdict', 'unknown')})"
                    )
                else:
                    parts.append(f"- {ind}")

        # MITRE techniques
        techniques = incident_data.get("mitre_techniques", [])
        if techniques:
            parts.append("\n### MITRE ATT&CK Techniques")
            for tech in techniques[:5]:
                if isinstance(tech, dict):
                    parts.append(
                        f"- {tech.get('id', '')} - {tech.get('name', '')} "
                        f"({tech.get('tactic', '')})"
                    )
                else:
                    parts.append(f"- {tech}")

        # Evidence summary
        evidence = incident_data.get("evidence", [])
        if evidence:
            parts.append(f"\n### Evidence: {len(evidence)} items collected")

        return "\n".join(parts)

    def _format_conversation_history(self, history: list[dict[str, str]]) -> str:
        """Format conversation history for context."""
        if not history:
            return ""
        parts = ["## Previous Conversation"]
        for entry in history[-5:]:  # Last 5 exchanges
            role = entry.get("role", "user")
            content = entry.get("content", "")
            parts.append(f"{role}: {content}")
        return "\n".join(parts)

    def _assist_with_llm(
        self,
        incident_context: str,
        question: str,
        conversation_context: str,
    ) -> CopilotResponse:
        """Generate a response using the LLM provider."""
        from tw_ai.llm.base import Message, Role

        messages = [
            Message(role=Role.SYSTEM, content=self._system_prompt),
        ]

        # Add context
        context_parts = [incident_context]
        if conversation_context:
            context_parts.append(conversation_context)
        context_msg = "\n\n".join(context_parts)

        messages.append(Message(role=Role.USER, content=f"{context_msg}\n\nQuestion: {question}"))

        response = self._llm.complete(messages)  # type: ignore[union-attr]

        # Parse the response
        answer: str = response.content  # type: ignore[union-attr]
        sources = self._extract_sources(answer)
        actions = self._extract_suggestions(answer)
        followups = self._generate_followups(question)

        return CopilotResponse(
            answer=answer,
            sources=sources,
            suggested_actions=actions,
            suggested_followups=followups,
            rag_context_used=False,
        )

    def _assist_rule_based(
        self,
        incident_data: dict[str, Any],
        question: str,
    ) -> CopilotResponse:
        """Provide rule-based assistance without an LLM.

        Used as fallback when no LLM is configured.
        """
        question_lower = question.lower()
        answer_parts: list[str] = []
        actions: list[str] = []
        sources: list[str] = []

        severity = incident_data.get("severity", "unknown")
        verdict = incident_data.get("verdict", "unknown")
        alert_type = incident_data.get("alert_type", "unknown")
        indicators = incident_data.get("indicators", [])

        # Handle common question patterns
        if any(w in question_lower for w in ["what happened", "summarize", "summary", "explain"]):
            summary = incident_data.get("summary", "No summary available.")
            answer_parts.append(f"This is a {severity} severity {alert_type} incident.")
            answer_parts.append(f"Current verdict: {verdict}.")
            answer_parts.append(f"Summary: {summary}")
            if indicators:
                answer_parts.append(f"There are {len(indicators)} indicators identified.")
            sources.append("incident_data")

        elif any(w in question_lower for w in ["next step", "what should i do", "recommend"]):
            actions = self._suggest_actions_for_type(alert_type, severity, verdict)
            answer_parts.append(
                f"Based on the {severity} severity {alert_type} incident "
                f"with verdict '{verdict}', here are recommended next steps:"
            )
            for i, action in enumerate(actions, 1):
                answer_parts.append(f"{i}. {action}")
            sources.append("playbook_recommendations")

        elif any(w in question_lower for w in ["indicator", "ioc", "iocs"]):
            if indicators:
                answer_parts.append(f"Found {len(indicators)} indicators:")
                for ind in indicators[:10]:
                    if isinstance(ind, dict):
                        answer_parts.append(
                            f"- {ind.get('type', '?')}: {ind.get('value', '?')} "
                            f"({ind.get('verdict', '?')})"
                        )
                    else:
                        answer_parts.append(f"- {ind}")
            else:
                answer_parts.append("No indicators have been identified yet.")
            sources.append("incident_indicators")

        elif any(w in question_lower for w in ["mitre", "technique", "tactic", "att&ck"]):
            techniques = incident_data.get("mitre_techniques", [])
            if techniques:
                answer_parts.append("MITRE ATT&CK techniques identified:")
                for tech in techniques:
                    if isinstance(tech, dict):
                        answer_parts.append(
                            f"- {tech.get('id', '?')}: {tech.get('name', '?')} "
                            f"(Tactic: {tech.get('tactic', '?')})"
                        )
                    else:
                        answer_parts.append(f"- {tech}")
            else:
                answer_parts.append("No MITRE ATT&CK techniques have been mapped yet.")
            sources.append("mitre_mapping")

        elif any(w in question_lower for w in ["severity", "how bad", "how serious", "risk"]):
            answer_parts.append(f"This incident is classified as {severity} severity.")
            if verdict == "true_positive":
                answer_parts.append(
                    "The verdict is true positive, indicating confirmed malicious activity."
                )
            elif verdict == "false_positive":
                answer_parts.append(
                    "The verdict is false positive. Consider closing or downgrading."
                )
            elif verdict == "suspicious":
                answer_parts.append(
                    "The verdict is suspicious. Further investigation is recommended."
                )
            sources.append("incident_metadata")

        else:
            answer_parts.append(
                f"I can help you investigate this {alert_type} incident. "
                f"It is currently rated {severity} severity with verdict '{verdict}'."
            )
            answer_parts.append(
                "Try asking about indicators, MITRE techniques, "
                "recommended next steps, or a summary of the incident."
            )

        answer = "\n".join(answer_parts)
        followups = self._generate_followups(question)

        return CopilotResponse(
            answer=answer,
            sources=sources,
            suggested_actions=actions,
            suggested_followups=followups,
            confidence=0.7 if answer_parts else 0.3,
        )

    @staticmethod
    def _suggest_actions_for_type(
        alert_type: str,
        severity: str,
        verdict: str,
    ) -> list[str]:
        """Generate suggested actions based on alert type and context."""
        actions: list[str] = []

        if verdict == "true_positive":
            if severity in ("critical", "high"):
                actions.append("Escalate to incident response team immediately")
                actions.append("Isolate affected endpoints to prevent lateral movement")
            actions.append("Collect forensic evidence from affected systems")
            actions.append("Block identified malicious indicators at the perimeter")

        elif verdict == "suspicious":
            actions.append("Gather additional evidence to confirm or deny the alert")
            actions.append("Check threat intelligence feeds for related indicators")
            actions.append("Review logs for related activity in the past 24 hours")

        elif verdict == "false_positive":
            actions.append("Document the false positive for tuning detection rules")
            actions.append("Consider adding an exception rule if this pattern recurs")

        # Type-specific suggestions
        alert_lower = alert_type.lower() if alert_type else ""
        if "phishing" in alert_lower:
            actions.append("Check if the user clicked on any links or opened attachments")
            actions.append("Quarantine the email and similar messages from the same sender")
        elif "malware" in alert_lower:
            actions.append("Run a full scan on the affected endpoint")
            actions.append("Check for persistence mechanisms")
        elif "login" in alert_lower or "brute" in alert_lower:
            actions.append("Review the user's recent authentication history")
            actions.append("Consider temporarily disabling the account if compromised")

        return actions

    @staticmethod
    def _extract_sources(text: str) -> list[str]:
        """Extract source references from LLM response text."""
        sources: list[str] = []
        # Look for [Source: ...] patterns
        source_pattern = re.compile(r"\[(?:Source|Ref|Citation):\s*([^\]]+)\]")
        for match in source_pattern.finditer(text):
            sources.append(match.group(1).strip())
        return sources

    @staticmethod
    def _extract_suggestions(text: str) -> list[str]:
        """Extract action suggestions from LLM response text."""
        actions: list[str] = []
        # Look for numbered action items
        action_pattern = re.compile(r"^\d+\.\s+(.+)$", re.MULTILINE)
        for match in action_pattern.finditer(text):
            action = match.group(1).strip()
            if any(
                kw in action.lower()
                for kw in [
                    "investigate",
                    "check",
                    "review",
                    "block",
                    "isolate",
                    "collect",
                    "scan",
                    "monitor",
                    "escalate",
                    "verify",
                ]
            ):
                actions.append(action)
        return actions

    @staticmethod
    def _generate_followups(question: str) -> list[str]:
        """Generate suggested follow-up questions."""
        question_lower = question.lower()
        followups: list[str] = []

        if "summary" in question_lower or "explain" in question_lower:
            followups.append("What are the indicators of compromise?")
            followups.append("What MITRE techniques are involved?")
        elif "indicator" in question_lower or "ioc" in question_lower:
            followups.append("Are any of these indicators seen in other incidents?")
            followups.append("What actions should I take based on these indicators?")
        elif "mitre" in question_lower or "technique" in question_lower:
            followups.append("What detection rules cover these techniques?")
            followups.append("Are there similar incidents using these techniques?")
        elif "next step" in question_lower or "recommend" in question_lower:
            followups.append("Can you explain the severity assessment?")
            followups.append("Are there related incidents I should look at?")
        else:
            followups.append("What happened in this incident?")
            followups.append("What are the recommended next steps?")

        return followups


__all__ = [
    "COPILOT_SYSTEM_PROMPT",
    "CopilotResponse",
    "InvestigationCopilot",
]
