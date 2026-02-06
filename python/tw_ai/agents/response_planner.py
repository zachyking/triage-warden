"""Response planning agent for automated incident response."""

from __future__ import annotations

import json
import uuid
from enum import Enum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


class RiskLevel(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, RiskLevel):
            return NotImplemented
        order = {
            RiskLevel.NONE: 0,
            RiskLevel.LOW: 1,
            RiskLevel.MEDIUM: 2,
            RiskLevel.HIGH: 3,
            RiskLevel.CRITICAL: 4,
        }
        return order[self] < order[other]

    def __le__(self, other: object) -> bool:
        if not isinstance(other, RiskLevel):
            return NotImplemented
        return self == other or self.__lt__(other)

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, RiskLevel):
            return NotImplemented
        result = self.__le__(other)
        if result is NotImplemented:
            return NotImplemented
        return not result

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, RiskLevel):
            return NotImplemented
        result = self.__lt__(other)
        if result is NotImplemented:
            return NotImplemented
        return not result


class ResponseStep(BaseModel):
    """A single step in a response plan."""

    id: str
    name: str
    description: str
    action: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    risk_level: RiskLevel = RiskLevel.LOW
    requires_approval: bool = False
    estimated_duration_secs: int = 60
    depends_on: list[str] = Field(default_factory=list)
    rollback_action: str | None = None
    rollback_parameters: dict[str, Any] = Field(default_factory=dict)


class ResponsePlan(BaseModel):
    """A multi-step automated response plan."""

    id: str
    incident_id: str
    summary: str
    steps: list[ResponseStep] = Field(default_factory=list)
    total_risk: RiskLevel = RiskLevel.LOW
    estimated_duration_secs: int = 0
    requires_human_review: bool = True
    reasoning: str = ""
    mitre_techniques: list[str] = Field(default_factory=list)


class PlanValidationResult(BaseModel):
    """Result of validating a response plan."""

    valid: bool
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    blocked_steps: list[str] = Field(default_factory=list)
    requires_approval_steps: list[str] = Field(default_factory=list)


# Default incident type to response step mappings
_PHISHING_STEPS: list[dict[str, Any]] = [
    {
        "name": "Quarantine email",
        "description": "Quarantine the suspected phishing email from all recipients",
        "action": "quarantine_email",
        "risk_level": "medium",
        "estimated_duration_secs": 30,
    },
    {
        "name": "Block sender domain",
        "description": "Block the sender domain to prevent further phishing attempts",
        "action": "block_domain",
        "risk_level": "medium",
        "estimated_duration_secs": 30,
    },
    {
        "name": "Search for related emails",
        "description": "Search logs for other emails from the same sender or campaign",
        "action": "search_logs",
        "risk_level": "low",
        "estimated_duration_secs": 120,
    },
    {
        "name": "Notify affected users",
        "description": "Send notification to users who received the phishing email",
        "action": "notify_user",
        "risk_level": "low",
        "estimated_duration_secs": 30,
    },
    {
        "name": "Create tracking ticket",
        "description": "Create incident ticket for tracking and documentation",
        "action": "create_ticket",
        "risk_level": "low",
        "estimated_duration_secs": 15,
    },
]

_MALWARE_STEPS: list[dict[str, Any]] = [
    {
        "name": "Isolate infected host",
        "description": "Isolate the infected host from the network to prevent lateral movement",
        "action": "isolate_host",
        "risk_level": "high",
        "requires_approval": True,
        "estimated_duration_secs": 60,
        "rollback_action": "unisolate_host",
    },
    {
        "name": "Block malware hash",
        "description": "Block the malware file hash across all endpoints",
        "action": "block_hash",
        "risk_level": "medium",
        "estimated_duration_secs": 30,
    },
    {
        "name": "Scan host for artifacts",
        "description": "Run a deep scan on the infected host for additional malware artifacts",
        "action": "scan_host",
        "risk_level": "low",
        "estimated_duration_secs": 300,
    },
    {
        "name": "Search for lateral movement",
        "description": "Search logs for signs of lateral movement from the infected host",
        "action": "search_logs",
        "risk_level": "low",
        "estimated_duration_secs": 120,
    },
    {
        "name": "Create tracking ticket",
        "description": "Create incident ticket for tracking and documentation",
        "action": "create_ticket",
        "risk_level": "low",
        "estimated_duration_secs": 15,
    },
]

_BRUTE_FORCE_STEPS: list[dict[str, Any]] = [
    {
        "name": "Block attacker IP",
        "description": "Block the source IP address performing brute force attempts",
        "action": "block_ip",
        "risk_level": "medium",
        "estimated_duration_secs": 30,
    },
    {
        "name": "Reset compromised password",
        "description": "Reset the password for the targeted account",
        "action": "reset_password",
        "risk_level": "high",
        "requires_approval": True,
        "estimated_duration_secs": 30,
    },
    {
        "name": "Revoke active sessions",
        "description": "Revoke all active sessions for the targeted account",
        "action": "revoke_sessions",
        "risk_level": "high",
        "requires_approval": True,
        "estimated_duration_secs": 30,
    },
    {
        "name": "Search for successful logins",
        "description": "Search logs for any successful logins from the attacker IP",
        "action": "search_logs",
        "risk_level": "low",
        "estimated_duration_secs": 120,
    },
    {
        "name": "Notify account owner",
        "description": "Notify the account owner about the brute force attempt",
        "action": "notify_user",
        "risk_level": "low",
        "estimated_duration_secs": 30,
    },
    {
        "name": "Create tracking ticket",
        "description": "Create incident ticket for tracking and documentation",
        "action": "create_ticket",
        "risk_level": "low",
        "estimated_duration_secs": 15,
    },
]

_DATA_EXFIL_STEPS: list[dict[str, Any]] = [
    {
        "name": "Isolate source host",
        "description": "Isolate the host performing data exfiltration",
        "action": "isolate_host",
        "risk_level": "high",
        "requires_approval": True,
        "estimated_duration_secs": 60,
        "rollback_action": "unisolate_host",
    },
    {
        "name": "Block destination IP",
        "description": "Block the destination IP/domain receiving exfiltrated data",
        "action": "block_ip",
        "risk_level": "medium",
        "estimated_duration_secs": 30,
    },
    {
        "name": "Disable user account",
        "description": "Disable the user account associated with the exfiltration",
        "action": "disable_user",
        "risk_level": "high",
        "requires_approval": True,
        "estimated_duration_secs": 30,
        "rollback_action": "enable_user",
    },
    {
        "name": "Search for data access patterns",
        "description": "Search logs for unusual data access patterns by the user",
        "action": "search_logs",
        "risk_level": "low",
        "estimated_duration_secs": 180,
    },
    {
        "name": "Create tracking ticket",
        "description": "Create incident ticket for tracking and documentation",
        "action": "create_ticket",
        "risk_level": "low",
        "estimated_duration_secs": 15,
    },
]

_DEFAULT_STEPS_BY_TYPE: dict[str, list[dict[str, Any]]] = {
    "phishing": _PHISHING_STEPS,
    "malware": _MALWARE_STEPS,
    "brute_force": _BRUTE_FORCE_STEPS,
    "data_exfiltration": _DATA_EXFIL_STEPS,
}

_SEVERITY_TO_RISK: dict[str, RiskLevel] = {
    "critical": RiskLevel.CRITICAL,
    "high": RiskLevel.HIGH,
    "medium": RiskLevel.MEDIUM,
    "low": RiskLevel.LOW,
    "informational": RiskLevel.NONE,
}

# Actions that are forbidden by default
_FORBIDDEN_ACTIONS: set[str] = {
    "delete_user",
    "wipe_host",
    "delete_all_emails",
    "modify_firewall",
}

# Max steps per plan
_MAX_PLAN_STEPS = 20


class ResponsePlanningAgent:
    """Plans multi-step incident responses using AI reasoning."""

    def __init__(self, llm_provider: Any = None, policy_config: dict[str, Any] | None = None):
        self._llm = llm_provider
        self._policy_config = policy_config or {}
        self._forbidden_actions: set[str] = set(
            self._policy_config.get("forbidden_actions", _FORBIDDEN_ACTIONS)
        )
        self._protected_targets: list[str] = list(self._policy_config.get("protected_targets", []))
        self._max_risk_level: RiskLevel = RiskLevel(
            self._policy_config.get("max_risk_level", "critical")
        )

    async def plan_response(
        self,
        incident_summary: str,
        incident_severity: str,
        incident_type: str,
        available_actions: list[str] | None = None,
        context: dict[str, Any] | None = None,
    ) -> ResponsePlan:
        """Create a multi-step response plan for an incident."""
        incident_id = (context or {}).get("incident_id", str(uuid.uuid4()))

        if self._llm is not None:
            try:
                prompt = self._build_planning_prompt(
                    incident_summary,
                    incident_severity,
                    incident_type,
                    available_actions,
                    context,
                )
                if callable(self._llm) and not hasattr(self._llm, "generate"):
                    response = await self._llm(prompt)
                else:
                    response = await self._llm.generate(prompt)
                plan = self._parse_plan(response, incident_id)
                plan.total_risk = self._assess_total_risk(plan.steps)
                plan.estimated_duration_secs = sum(s.estimated_duration_secs for s in plan.steps)
                plan.requires_human_review = any(s.requires_approval for s in plan.steps)
                return plan
            except Exception:
                logger.warning(
                    "LLM planning failed, falling back to default plan",
                    incident_type=incident_type,
                    exc_info=True,
                )

        return self._default_plan(incident_summary, incident_severity, incident_type)

    def validate_plan(self, plan: ResponsePlan) -> PlanValidationResult:
        """Validate a response plan against policies."""
        warnings: list[str] = []
        errors: list[str] = []
        blocked_steps: list[str] = []
        requires_approval_steps: list[str] = []

        if not plan.steps:
            errors.append("Plan has no steps")
            return PlanValidationResult(
                valid=False,
                warnings=warnings,
                errors=errors,
                blocked_steps=blocked_steps,
                requires_approval_steps=requires_approval_steps,
            )

        if len(plan.steps) > _MAX_PLAN_STEPS:
            errors.append(f"Plan exceeds maximum of {_MAX_PLAN_STEPS} steps")

        step_ids = {s.id for s in plan.steps}

        for step in plan.steps:
            # Check forbidden actions
            if step.action in self._forbidden_actions:
                errors.append(f"Step '{step.id}': action '{step.action}' is forbidden")
                blocked_steps.append(step.id)

            # Check risk level
            if step.risk_level > self._max_risk_level:
                errors.append(
                    f"Step '{step.id}': risk level '{step.risk_level.value}' "
                    f"exceeds maximum '{self._max_risk_level.value}'"
                )
                blocked_steps.append(step.id)

            # Check protected targets
            for target_pattern in self._protected_targets:
                for param_val in step.parameters.values():
                    if isinstance(param_val, str) and target_pattern in param_val:
                        errors.append(
                            f"Step '{step.id}': targets protected"
                            f" entity matching '{target_pattern}'"
                        )
                        blocked_steps.append(step.id)

            # Validate dependencies
            for dep in step.depends_on:
                if dep not in step_ids:
                    errors.append(f"Step '{step.id}': dependency '{dep}' not found in plan")

            # Track approval requirements
            if step.requires_approval:
                requires_approval_steps.append(step.id)

            # Warn on high risk without approval
            if step.risk_level >= RiskLevel.HIGH and not step.requires_approval:
                warnings.append(
                    f"Step '{step.id}': high-risk action '{step.action}' "
                    "does not require approval"
                )

            # Warn on missing rollback for high-risk steps
            if step.risk_level >= RiskLevel.HIGH and not step.rollback_action:
                warnings.append(
                    f"Step '{step.id}': high-risk action '{step.action}' "
                    "has no rollback action defined"
                )

        # Check for circular dependencies
        if self._has_circular_deps(plan.steps):
            errors.append("Plan has circular dependencies")

        valid = len(errors) == 0
        return PlanValidationResult(
            valid=valid,
            warnings=warnings,
            errors=errors,
            blocked_steps=list(set(blocked_steps)),
            requires_approval_steps=requires_approval_steps,
        )

    def _has_circular_deps(self, steps: list[ResponseStep]) -> bool:
        """Check for circular dependencies using DFS."""
        graph: dict[str, list[str]] = {s.id: list(s.depends_on) for s in steps}
        visited: set[str] = set()
        rec_stack: set[str] = set()

        def dfs(node: str) -> bool:
            visited.add(node)
            rec_stack.add(node)
            for neighbor in graph.get(node, []):
                if neighbor not in visited:
                    if dfs(neighbor):
                        return True
                elif neighbor in rec_stack:
                    return True
            rec_stack.discard(node)
            return False

        for step_id in graph:
            if step_id not in visited:
                if dfs(step_id):
                    return True
        return False

    def _build_planning_prompt(
        self,
        incident_summary: str,
        incident_severity: str,
        incident_type: str,
        available_actions: list[str] | None = None,
        context: dict[str, Any] | None = None,
    ) -> str:
        """Build the LLM prompt for response planning."""
        actions_str = ""
        if available_actions:
            actions_str = f"\nAvailable actions: {', '.join(available_actions)}"

        context_str = ""
        if context:
            safe_context = {
                k: v
                for k, v in context.items()
                if k not in ("credentials", "secrets", "tokens", "api_keys")
            }
            context_str = f"\nAdditional context: {json.dumps(safe_context, default=str)}"

        return (
            "You are a security incident response planner. Create a structured "
            "multi-step response plan for the following incident.\n\n"
            f"Incident Type: {incident_type}\n"
            f"Severity: {incident_severity}\n"
            f"Summary: {incident_summary}\n"
            f"{actions_str}{context_str}\n\n"
            "Respond with a JSON object containing:\n"
            "- summary: brief description of the response plan\n"
            "- reasoning: why this plan was chosen\n"
            "- mitre_techniques: list of relevant MITRE ATT&CK technique IDs\n"
            "- steps: list of step objects, each with:\n"
            "  - name: step name\n"
            "  - description: what the step does\n"
            "  - action: action identifier\n"
            "  - parameters: dict of parameters\n"
            "  - risk_level: none/low/medium/high/critical\n"
            "  - requires_approval: boolean\n"
            "  - estimated_duration_secs: integer\n"
            "  - depends_on: list of step IDs this depends on\n"
            "  - rollback_action: optional rollback action name\n"
            "  - rollback_parameters: optional rollback params dict\n\n"
            "Respond ONLY with valid JSON."
        )

    def _parse_plan(self, response: str, incident_id: str) -> ResponsePlan:
        """Parse LLM response into a ResponsePlan."""
        # Strip markdown code fences if present
        text = response.strip()
        if text.startswith("```"):
            lines = text.split("\n")
            lines = lines[1:]  # skip opening fence
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            text = "\n".join(lines)

        data = json.loads(text)
        plan_id = str(uuid.uuid4())

        steps: list[ResponseStep] = []
        for i, step_data in enumerate(data.get("steps", [])):
            step_id = step_data.get("id", f"step-{i + 1}")
            steps.append(
                ResponseStep(
                    id=step_id,
                    name=step_data.get("name", f"Step {i + 1}"),
                    description=step_data.get("description", ""),
                    action=step_data.get("action", "unknown"),
                    parameters=step_data.get("parameters", {}),
                    risk_level=RiskLevel(step_data.get("risk_level", "low")),
                    requires_approval=step_data.get("requires_approval", False),
                    estimated_duration_secs=step_data.get("estimated_duration_secs", 60),
                    depends_on=step_data.get("depends_on", []),
                    rollback_action=step_data.get("rollback_action"),
                    rollback_parameters=step_data.get("rollback_parameters", {}),
                )
            )

        return ResponsePlan(
            id=plan_id,
            incident_id=incident_id,
            summary=data.get("summary", "AI-generated response plan"),
            steps=steps,
            reasoning=data.get("reasoning", ""),
            mitre_techniques=data.get("mitre_techniques", []),
        )

    def _assess_total_risk(self, steps: list[ResponseStep]) -> RiskLevel:
        """Assess the overall risk level of a plan."""
        if not steps:
            return RiskLevel.NONE
        return max(steps, key=lambda s: s.risk_level).risk_level

    def _default_plan(
        self,
        incident_summary: str,
        incident_severity: str,
        incident_type: str,
    ) -> ResponsePlan:
        """Generate a sensible default plan when no LLM is available."""
        plan_id = str(uuid.uuid4())
        incident_id = str(uuid.uuid4())

        step_templates = _DEFAULT_STEPS_BY_TYPE.get(incident_type)
        if step_templates is None:
            # Generic fallback: search logs and create ticket
            step_templates = [
                {
                    "name": "Search related logs",
                    "description": (
                        "Search logs for indicators related to:" f" {incident_summary[:100]}"
                    ),
                    "action": "search_logs",
                    "risk_level": "low",
                    "estimated_duration_secs": 120,
                },
                {
                    "name": "Create tracking ticket",
                    "description": "Create incident ticket for tracking and documentation",
                    "action": "create_ticket",
                    "risk_level": "low",
                    "estimated_duration_secs": 15,
                },
            ]

        steps: list[ResponseStep] = []
        prev_id: str | None = None
        for i, tmpl in enumerate(step_templates):
            step_id = f"step-{i + 1}"
            depends_on: list[str] = []
            if prev_id is not None:
                depends_on = [prev_id]

            rollback_params: dict[str, Any] = {}
            rollback_action = tmpl.get("rollback_action")
            if rollback_action:
                rollback_params = tmpl.get("rollback_parameters", {})

            steps.append(
                ResponseStep(
                    id=step_id,
                    name=tmpl["name"],
                    description=tmpl["description"],
                    action=tmpl["action"],
                    parameters=tmpl.get("parameters", {}),
                    risk_level=RiskLevel(tmpl.get("risk_level", "low")),
                    requires_approval=tmpl.get("requires_approval", False),
                    estimated_duration_secs=tmpl.get("estimated_duration_secs", 60),
                    depends_on=depends_on,
                    rollback_action=rollback_action,
                    rollback_parameters=rollback_params,
                )
            )
            prev_id = step_id

        total_risk = self._assess_total_risk(steps)
        total_duration = sum(s.estimated_duration_secs for s in steps)
        requires_review = any(s.requires_approval for s in steps)

        return ResponsePlan(
            id=plan_id,
            incident_id=incident_id,
            summary=f"Default response plan for {incident_type} incident: {incident_summary[:80]}",
            steps=steps,
            total_risk=total_risk,
            estimated_duration_secs=total_duration,
            requires_human_review=requires_review,
            reasoning=(
                f"Default plan generated for {incident_type} incident"
                f" with {incident_severity} severity"
            ),
            mitre_techniques=[],
        )
