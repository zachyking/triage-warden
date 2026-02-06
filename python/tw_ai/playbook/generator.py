"""Dynamic playbook step generator using AI.

This module provides:
- AI-driven generation of playbook steps based on incident context
- Default step generation when no LLM is available
- Pydantic models for generated steps and generation context
"""

from __future__ import annotations

import json
import re
from typing import Any, Protocol

from pydantic import BaseModel, Field


class LLMProvider(Protocol):
    """Protocol for LLM providers used by the step generator."""

    async def generate(self, prompt: str) -> str:
        """Generate a response from the given prompt."""
        ...


class GeneratedStep(BaseModel):
    """A dynamically generated playbook step."""

    name: str
    action: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    requires_approval: bool = False
    risk_level: str = Field(
        default="low",
        description="Risk level of the step",
        pattern="^(none|low|medium|high|critical)$",
    )
    rationale: str = ""
    estimated_duration_secs: int = 60


class StepGenerationContext(BaseModel):
    """Context for dynamic step generation."""

    incident_summary: str
    incident_severity: str
    incident_type: str
    available_actions: list[str] = Field(default_factory=list)
    organization_policies: dict[str, Any] = Field(default_factory=dict)
    previous_step_results: list[dict[str, Any]] = Field(default_factory=list)


class DynamicStepGenerator:
    """Generates playbook steps dynamically using AI.

    When an LLM provider is configured, steps are generated based on
    incident context. Otherwise, sensible defaults are returned.
    """

    def __init__(self, llm_provider: LLMProvider | None = None) -> None:
        self._llm = llm_provider

    async def generate_steps(self, context: StepGenerationContext) -> list[GeneratedStep]:
        """Generate appropriate response steps based on incident context.

        Args:
            context: The incident and organizational context.

        Returns:
            List of generated playbook steps.
        """
        if self._llm is None:
            return self._default_steps(context)
        prompt = self._build_prompt(context)
        response = await self._llm.generate(prompt)
        return self._parse_steps(response)

    def _build_prompt(self, context: StepGenerationContext) -> str:
        """Build LLM prompt for step generation.

        Args:
            context: The generation context.

        Returns:
            A prompt string for the LLM.
        """
        actions_section = ""
        if context.available_actions:
            actions_list = "\n".join(f"  - {a}" for a in context.available_actions)
            actions_section = f"\nAvailable actions:\n{actions_list}\n"

        policies_section = ""
        if context.organization_policies:
            policies_json = json.dumps(context.organization_policies, indent=2)
            policies_section = f"\nOrganization policies:\n{policies_json}\n"

        previous_section = ""
        if context.previous_step_results:
            prev_json = json.dumps(context.previous_step_results, indent=2)
            previous_section = f"\nPrevious step results:\n{prev_json}\n"

        return (
            "You are a security incident response advisor."
            " Generate a list of playbook steps to respond"
            " to the following incident.\n"
            "\n"
            f"Incident Summary: {context.incident_summary}\n"
            f"Incident Severity: {context.incident_severity}\n"
            f"Incident Type: {context.incident_type}\n"
            f"{actions_section}{policies_section}"
            f"{previous_section}\n"
            "Respond with a JSON array of steps."
            " Each step must have:\n"
            '- "name": human-readable step name\n'
            '- "action": the action identifier to execute\n'
            '- "parameters": dict of parameters for the'
            " action\n"
            '- "requires_approval": boolean, true for'
            " high-risk actions\n"
            '- "risk_level": one of "low", "medium",'
            ' "high", "critical"\n'
            '- "rationale": why this step is recommended\n'
            '- "estimated_duration_secs": estimated time'
            " in seconds\n"
            "\n"
            "Only output the JSON array, no other text."
        )

    def _parse_steps(self, response: str) -> list[GeneratedStep]:
        """Parse LLM response into GeneratedStep objects.

        Args:
            response: Raw LLM response string.

        Returns:
            List of parsed steps, falling back to empty list on parse error.
        """
        # Try to extract JSON array from the response
        text = response.strip()

        # Try direct parse
        try:
            data = json.loads(text)
            if isinstance(data, list):
                return [GeneratedStep(**item) for item in data]
        except (json.JSONDecodeError, TypeError, ValueError):
            pass

        # Try extracting JSON from markdown code block
        match = re.search(r"```(?:json)?\s*\n?(.*?)\n?```", text, re.DOTALL)
        if match:
            try:
                data = json.loads(match.group(1))
                if isinstance(data, list):
                    return [GeneratedStep(**item) for item in data]
            except (json.JSONDecodeError, TypeError, ValueError):
                pass

        # Try finding an array in the text
        match = re.search(r"\[.*\]", text, re.DOTALL)
        if match:
            try:
                data = json.loads(match.group(0))
                if isinstance(data, list):
                    return [GeneratedStep(**item) for item in data]
            except (json.JSONDecodeError, TypeError, ValueError):
                pass

        return []

    def _default_steps(self, context: StepGenerationContext) -> list[GeneratedStep]:
        """Return sensible default steps when no LLM is available.

        Generates a standard incident response workflow based on severity
        and incident type.

        Args:
            context: The generation context.

        Returns:
            List of default playbook steps.
        """
        steps: list[GeneratedStep] = []

        # Always start with evidence collection
        steps.append(
            GeneratedStep(
                name="Collect Evidence",
                action="collect_evidence",
                parameters={"incident_type": context.incident_type},
                requires_approval=False,
                risk_level="low",
                rationale="Gather initial evidence before taking action",
                estimated_duration_secs=30,
            )
        )

        # Enrichment step
        steps.append(
            GeneratedStep(
                name="Enrich Indicators",
                action="enrich_indicators",
                parameters={"incident_type": context.incident_type},
                requires_approval=False,
                risk_level="low",
                rationale="Enrich indicators with threat intelligence",
                estimated_duration_secs=45,
            )
        )

        # Severity-dependent steps
        severity = context.incident_severity.lower()

        if severity in ("critical", "high"):
            steps.append(
                GeneratedStep(
                    name="Notify Security Team",
                    action="notify_team",
                    parameters={"channel": "security-alerts", "priority": "high"},
                    requires_approval=False,
                    risk_level="low",
                    rationale="Immediately notify the security team for high-severity incidents",
                    estimated_duration_secs=5,
                )
            )

        if severity == "critical":
            steps.append(
                GeneratedStep(
                    name="Isolate Affected Systems",
                    action="isolate_host",
                    parameters={},
                    requires_approval=True,
                    risk_level="high",
                    rationale="Isolate affected systems to prevent lateral movement",
                    estimated_duration_secs=120,
                )
            )

        # Type-specific steps
        incident_type = context.incident_type.lower()

        if "phishing" in incident_type:
            steps.append(
                GeneratedStep(
                    name="Block Sender Domain",
                    action="block_sender",
                    parameters={},
                    requires_approval=severity not in ("critical", "high"),
                    risk_level="medium",
                    rationale="Block the phishing sender to prevent further emails",
                    estimated_duration_secs=30,
                )
            )

        if "malware" in incident_type:
            steps.append(
                GeneratedStep(
                    name="Submit to Sandbox",
                    action="sandbox_submit",
                    parameters={},
                    requires_approval=False,
                    risk_level="low",
                    rationale="Analyze malware sample in sandbox environment",
                    estimated_duration_secs=300,
                )
            )

        if "unauthorized" in incident_type or "access" in incident_type:
            steps.append(
                GeneratedStep(
                    name="Revoke Access",
                    action="revoke_access",
                    parameters={},
                    requires_approval=True,
                    risk_level="high",
                    rationale="Revoke unauthorized access to prevent further damage",
                    estimated_duration_secs=60,
                )
            )

        # Always end with documentation
        steps.append(
            GeneratedStep(
                name="Document Findings",
                action="create_report",
                parameters={"incident_type": context.incident_type},
                requires_approval=False,
                risk_level="low",
                rationale="Document findings and actions taken for the incident record",
                estimated_duration_secs=60,
            )
        )

        return steps
