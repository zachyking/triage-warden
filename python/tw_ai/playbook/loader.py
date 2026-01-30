"""Playbook loader for parsing and validating YAML playbook definitions.

This module provides:
- YAML playbook parsing with schema validation
- Playbook data models using Pydantic v2
- Validation of playbook structure and references
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import structlog
import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

logger = structlog.get_logger()


# =============================================================================
# Exceptions
# =============================================================================


class PlaybookValidationError(Exception):
    """Raised when playbook validation fails."""

    def __init__(self, message: str, errors: list[str] | None = None):
        super().__init__(message)
        self.errors = errors or []


# =============================================================================
# Playbook Models
# =============================================================================


class Condition(BaseModel):
    """A condition for branching or step execution."""

    model_config = ConfigDict(extra="allow")

    verdict: str | None = None
    confidence_above: float | None = None
    confidence_below: float | None = None
    confidence_between: list[float] | None = None
    expression: str | None = None  # Custom expression like "input.reported_by is not null"

    @field_validator("confidence_above", "confidence_below")
    @classmethod
    def validate_confidence_range(cls, v: float | None) -> float | None:
        """Validate confidence is between 0 and 1."""
        if v is not None and not 0.0 <= v <= 1.0:
            raise ValueError(f"Confidence must be between 0 and 1, got {v}")
        return v

    @field_validator("confidence_between")
    @classmethod
    def validate_confidence_between(cls, v: list[float] | None) -> list[float] | None:
        """Validate confidence_between has exactly two values in valid range."""
        if v is not None:
            if len(v) != 2:
                raise ValueError("confidence_between must have exactly 2 values")
            if not all(0.0 <= x <= 1.0 for x in v):
                raise ValueError("confidence_between values must be between 0 and 1")
            if v[0] >= v[1]:
                raise ValueError("confidence_between[0] must be less than confidence_between[1]")
        return v

    def evaluate(self, context: dict[str, Any]) -> bool:
        """Evaluate this condition against the given context.

        Args:
            context: Execution context containing stage results and variables

        Returns:
            True if condition is satisfied, False otherwise
        """
        # Find verdict and confidence from any stage that has them
        # Prioritize ai_analysis stage, then search other stages
        current_verdict = None
        current_confidence = None

        # First check ai_analysis stage (common convention)
        ai_analysis = context.get("ai_analysis", {})
        if isinstance(ai_analysis, dict):
            current_verdict = ai_analysis.get("verdict")
            current_confidence = ai_analysis.get("confidence")

        # If not found, search all stages for verdict/confidence
        if current_verdict is None or current_confidence is None:
            for key, value in context.items():
                if key in ("input", "trigger"):
                    continue
                if isinstance(value, dict):
                    if current_verdict is None and "verdict" in value:
                        current_verdict = value["verdict"]
                    if current_confidence is None and "confidence" in value:
                        current_confidence = value["confidence"]
                    if current_verdict is not None and current_confidence is not None:
                        break

        # Convert confidence to 0-1 scale if it's 0-100
        if current_confidence is not None and current_confidence > 1:
            current_confidence = current_confidence / 100.0

        # Check verdict condition
        if self.verdict is not None:
            if current_verdict != self.verdict:
                return False

        # Check confidence_above
        if self.confidence_above is not None:
            if current_confidence is None or current_confidence <= self.confidence_above:
                return False

        # Check confidence_below
        if self.confidence_below is not None:
            if current_confidence is None or current_confidence >= self.confidence_below:
                return False

        # Check confidence_between
        if self.confidence_between is not None:
            if current_confidence is None:
                return False
            low, high = self.confidence_between
            if not (low <= current_confidence <= high):
                return False

        # Check custom expression
        if self.expression is not None:
            if not self._evaluate_expression(self.expression, context):
                return False

        return True

    def _evaluate_expression(self, expr: str, context: dict[str, Any]) -> bool:
        """Evaluate a custom expression against the context.

        Supports simple expressions like:
        - "input.reported_by is not null"
        - "extraction.urls is not empty"
        """
        # Handle "is not null" pattern
        if "is not null" in expr:
            path = expr.replace("is not null", "").strip()
            value = self._resolve_path(path, context)
            return value is not None

        # Handle "is null" pattern
        if "is null" in expr:
            path = expr.replace("is null", "").strip()
            value = self._resolve_path(path, context)
            return value is None

        # Handle "is not empty" pattern
        if "is not empty" in expr:
            path = expr.replace("is not empty", "").strip()
            value = self._resolve_path(path, context)
            return value is not None and len(value) > 0

        # Handle "is empty" pattern
        if "is empty" in expr:
            path = expr.replace("is empty", "").strip()
            value = self._resolve_path(path, context)
            return value is None or len(value) == 0

        logger.warning("unknown_expression_format", expression=expr)
        return False

    def _resolve_path(self, path: str, context: dict[str, Any]) -> Any:
        """Resolve a dotted path like 'input.reported_by' from context."""
        parts = path.split(".")
        value = context
        for part in parts:
            if isinstance(value, dict):
                value = value.get(part)
            else:
                return None
        return value


class Step(BaseModel):
    """A single step in a playbook stage."""

    model_config = ConfigDict(extra="allow")

    action: str = Field(description="The action to execute")
    input: dict[str, Any] = Field(
        default_factory=dict, description="Input parameters for the action"
    )
    output: list[str] = Field(default_factory=list, description="Output variable names")
    conditions: list[Condition] = Field(
        default_factory=list, description="Conditions for step execution"
    )
    requires_approval: bool = Field(
        default=False, description="Whether this step requires human approval"
    )

    @field_validator("action")
    @classmethod
    def action_not_empty(cls, v: str) -> str:
        """Ensure action name is not empty."""
        if not v or not v.strip():
            raise ValueError("Action name cannot be empty")
        return v.strip()

    @field_validator("conditions", mode="before")
    @classmethod
    def parse_conditions(cls, v: Any) -> list[Condition]:
        """Parse conditions from various formats."""
        if v is None:
            return []
        if isinstance(v, list):
            result = []
            for item in v:
                if isinstance(item, Condition):
                    result.append(item)
                elif isinstance(item, dict):
                    result.append(Condition(**item))
                elif isinstance(item, str):
                    # Handle string conditions like "confidence_above: 0.95"
                    if ":" in item:
                        key, value = item.split(":", 1)
                        result.append(Condition(**{key.strip(): float(value.strip())}))
                    else:
                        result.append(Condition(expression=item))
            return result
        return []


class Branch(BaseModel):
    """A conditional branch in a decision stage."""

    model_config = ConfigDict(extra="allow")

    conditions: list[Condition] = Field(default_factory=list)
    steps: list[Step] = Field(default_factory=list)

    @field_validator("conditions", mode="before")
    @classmethod
    def parse_conditions(cls, v: Any) -> list[Condition]:
        """Parse conditions from various formats."""
        if v is None:
            return []
        if isinstance(v, list):
            result = []
            for item in v:
                if isinstance(item, Condition):
                    result.append(item)
                elif isinstance(item, dict):
                    result.append(Condition(**item))
            return result
        return []

    @field_validator("steps", mode="before")
    @classmethod
    def parse_steps(cls, v: Any) -> list[Step]:
        """Parse steps from various formats."""
        if v is None:
            return []
        if isinstance(v, list):
            result = []
            for item in v:
                if isinstance(item, Step):
                    result.append(item)
                elif isinstance(item, dict):
                    result.append(Step(**item))
            return result
        return []

    def evaluate_conditions(self, context: dict[str, Any]) -> bool:
        """Check if all conditions for this branch are satisfied."""
        return all(cond.evaluate(context) for cond in self.conditions)


class Stage(BaseModel):
    """A stage in the playbook workflow."""

    model_config = ConfigDict(extra="allow")

    name: str = Field(description="Stage name")
    description: str = Field(default="", description="Stage description")
    parallel: bool = Field(default=False, description="Whether to run steps in parallel")
    steps: list[Step] = Field(default_factory=list, description="Steps to execute")
    branches: dict[str, Branch] = Field(default_factory=dict, description="Conditional branches")

    @field_validator("name")
    @classmethod
    def name_not_empty(cls, v: str) -> str:
        """Ensure stage name is not empty."""
        if not v or not v.strip():
            raise ValueError("Stage name cannot be empty")
        return v.strip()

    @field_validator("steps", mode="before")
    @classmethod
    def parse_steps(cls, v: Any) -> list[Step]:
        """Parse steps from various formats."""
        if v is None:
            return []
        if isinstance(v, list):
            result = []
            for item in v:
                if isinstance(item, Step):
                    result.append(item)
                elif isinstance(item, dict):
                    result.append(Step(**item))
            return result
        return []

    @field_validator("branches", mode="before")
    @classmethod
    def parse_branches(cls, v: Any) -> dict[str, Branch]:
        """Parse branches from YAML format."""
        if v is None:
            return {}
        if isinstance(v, dict):
            result = {}
            for name, branch_data in v.items():
                if isinstance(branch_data, Branch):
                    result[name] = branch_data
                elif isinstance(branch_data, dict):
                    result[name] = Branch(**branch_data)
            return result
        return {}


class Trigger(BaseModel):
    """Trigger conditions for the playbook."""

    model_config = ConfigDict(extra="allow")

    sources: list[str] = Field(default_factory=list)
    alert_types: list[str] = Field(default_factory=list)


class InputParameter(BaseModel):
    """Input parameter definition."""

    model_config = ConfigDict(extra="allow")

    required: list[str] = Field(default_factory=list)
    optional: list[str] = Field(default_factory=list)


class SLA(BaseModel):
    """SLA configuration."""

    model_config = ConfigDict(extra="allow")

    time_to_triage: str = Field(default="5m")
    time_to_respond: str = Field(default="15m")
    escalation_on_breach: bool = Field(default=True)


class Metric(BaseModel):
    """Metric definition."""

    model_config = ConfigDict(extra="allow")

    name: str
    description: str = ""


class Playbook(BaseModel):
    """A complete playbook definition."""

    model_config = ConfigDict(extra="allow")

    name: str = Field(description="Playbook name")
    version: str = Field(default="1.0", description="Playbook version")
    description: str = Field(default="", description="Playbook description")
    trigger: Trigger = Field(default_factory=Trigger)
    input: InputParameter = Field(default_factory=InputParameter)
    stages: list[Stage] = Field(default_factory=list)
    sla: SLA = Field(default_factory=SLA)
    metrics: list[Metric] = Field(default_factory=list)

    @field_validator("name")
    @classmethod
    def name_not_empty(cls, v: str) -> str:
        """Ensure playbook name is not empty."""
        if not v or not v.strip():
            raise ValueError("Playbook name cannot be empty")
        return v.strip()

    @field_validator("stages", mode="before")
    @classmethod
    def parse_stages(cls, v: Any) -> list[Stage]:
        """Parse stages from various formats."""
        if v is None:
            return []
        if isinstance(v, list):
            result = []
            for item in v:
                if isinstance(item, Stage):
                    result.append(item)
                elif isinstance(item, dict):
                    result.append(Stage(**item))
            return result
        return []

    @field_validator("metrics", mode="before")
    @classmethod
    def parse_metrics(cls, v: Any) -> list[Metric]:
        """Parse metrics from various formats."""
        if v is None:
            return []
        if isinstance(v, list):
            result = []
            for item in v:
                if isinstance(item, Metric):
                    result.append(item)
                elif isinstance(item, dict):
                    result.append(Metric(**item))
            return result
        return []

    def get_stage(self, name: str) -> Stage | None:
        """Get a stage by name."""
        for stage in self.stages:
            if stage.name == name:
                return stage
        return None


# =============================================================================
# Validation Result
# =============================================================================


class ValidationResult(BaseModel):
    """Result of playbook validation."""

    model_config = ConfigDict(extra="allow")

    valid: bool = Field(description="Whether the playbook is valid")
    errors: list[str] = Field(default_factory=list, description="List of validation errors")
    warnings: list[str] = Field(default_factory=list, description="List of validation warnings")

    @classmethod
    def ok(cls) -> ValidationResult:
        """Create a successful validation result."""
        return cls(valid=True)

    @classmethod
    def error(cls, errors: list[str]) -> ValidationResult:
        """Create a failed validation result."""
        return cls(valid=False, errors=errors)


# =============================================================================
# Playbook Loader
# =============================================================================


class PlaybookLoader:
    """Loader for YAML playbook definitions.

    This class handles:
    - Loading playbook YAML files
    - Parsing into Playbook model
    - Validating structure and references

    Example:
        loader = PlaybookLoader()
        playbook = loader.load("path/to/playbook.yaml")
        result = loader.validate(playbook)
        if not result.valid:
            print(f"Validation errors: {result.errors}")
    """

    # Template variable pattern: {{ variable.path }}
    TEMPLATE_PATTERN = re.compile(r"\{\{\s*([a-zA-Z_][a-zA-Z0-9_.]*)\s*\}\}")

    def __init__(self) -> None:
        """Initialize the playbook loader."""
        self._logger = logger.bind(component="playbook_loader")

    def load(self, path: str | Path) -> Playbook:
        """Load a playbook from a YAML file.

        Args:
            path: Path to the YAML playbook file

        Returns:
            Parsed Playbook object

        Raises:
            FileNotFoundError: If the file doesn't exist
            PlaybookValidationError: If the YAML is invalid
        """
        path = Path(path)

        if not path.exists():
            raise FileNotFoundError(f"Playbook file not found: {path}")

        self._logger.info("loading_playbook", path=str(path))

        try:
            with open(path, encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            raise PlaybookValidationError(f"Invalid YAML: {e}")

        if not isinstance(data, dict):
            raise PlaybookValidationError("Playbook must be a YAML mapping")

        try:
            playbook = Playbook(**data)
        except Exception as e:
            raise PlaybookValidationError(f"Failed to parse playbook: {e}")

        self._logger.info(
            "playbook_loaded",
            name=playbook.name,
            version=playbook.version,
            stages=len(playbook.stages),
        )

        return playbook

    def load_from_string(self, content: str) -> Playbook:
        """Load a playbook from a YAML string.

        Args:
            content: YAML content as a string

        Returns:
            Parsed Playbook object

        Raises:
            PlaybookValidationError: If the YAML is invalid
        """
        try:
            data = yaml.safe_load(content)
        except yaml.YAMLError as e:
            raise PlaybookValidationError(f"Invalid YAML: {e}")

        if not isinstance(data, dict):
            raise PlaybookValidationError("Playbook must be a YAML mapping")

        try:
            playbook = Playbook(**data)
        except Exception as e:
            raise PlaybookValidationError(f"Failed to parse playbook: {e}")

        return playbook

    def validate(self, playbook: Playbook) -> ValidationResult:
        """Validate a playbook's structure and references.

        Checks:
        - Required fields are present
        - Stage names are unique
        - Template variables reference valid paths
        - Branch conditions are valid
        - Actions are defined

        Args:
            playbook: The playbook to validate

        Returns:
            ValidationResult with any errors or warnings
        """
        errors: list[str] = []
        warnings: list[str] = []

        self._logger.info("validating_playbook", name=playbook.name)

        # Check required fields
        if not playbook.name:
            errors.append("Playbook name is required")

        if not playbook.stages:
            errors.append("Playbook must have at least one stage")

        # Check stage names are unique
        stage_names = [s.name for s in playbook.stages]
        if len(stage_names) != len(set(stage_names)):
            duplicates = [n for n in stage_names if stage_names.count(n) > 1]
            errors.append(f"Duplicate stage names: {set(duplicates)}")

        # Validate each stage
        defined_outputs: set[str] = set()
        defined_outputs.add("input")  # Input is always available

        for stage in playbook.stages:
            stage_errors = self._validate_stage(stage, defined_outputs, playbook)
            errors.extend(stage_errors)

            # Add stage outputs for reference validation
            defined_outputs.add(stage.name)
            for step in stage.steps:
                for output in step.output:
                    defined_outputs.add(f"{stage.name}.{output}")

        # Check for warnings
        if not playbook.trigger.sources and not playbook.trigger.alert_types:
            warnings.append("Playbook has no trigger conditions defined")

        if not playbook.input.required:
            warnings.append("Playbook has no required input parameters")

        result = ValidationResult(
            valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
        )

        self._logger.info(
            "validation_complete",
            valid=result.valid,
            error_count=len(errors),
            warning_count=len(warnings),
        )

        return result

    def _validate_stage(
        self,
        stage: Stage,
        defined_outputs: set[str],
        playbook: Playbook,
    ) -> list[str]:
        """Validate a single stage."""
        errors: list[str] = []

        # Check for either steps or branches
        if not stage.steps and not stage.branches:
            errors.append(f"Stage '{stage.name}' has no steps or branches")

        # Validate steps
        for i, step in enumerate(stage.steps):
            step_errors = self._validate_step(step, defined_outputs, f"{stage.name}.steps[{i}]")
            errors.extend(step_errors)

        # Validate branches
        for branch_name, branch in stage.branches.items():
            branch_errors = self._validate_branch(
                branch, defined_outputs, f"{stage.name}.branches.{branch_name}"
            )
            errors.extend(branch_errors)

        return errors

    def _validate_step(
        self,
        step: Step,
        defined_outputs: set[str],
        context: str,
    ) -> list[str]:
        """Validate a single step."""
        errors: list[str] = []

        # Check action is defined
        if not step.action:
            errors.append(f"{context}: Action is required")

        # Validate template references in input
        template_refs = self._extract_template_references(step.input)
        for ref in template_refs:
            root = ref.split(".")[0]
            if root not in defined_outputs and root != "trigger":
                # Check if it's a full path reference
                if ref not in defined_outputs:
                    errors.append(f"{context}: Reference to undefined variable '{ref}'")

        return errors

    def _validate_branch(
        self,
        branch: Branch,
        defined_outputs: set[str],
        context: str,
    ) -> list[str]:
        """Validate a branch."""
        errors: list[str] = []

        if not branch.conditions:
            errors.append(f"{context}: Branch must have at least one condition")

        for i, step in enumerate(branch.steps):
            step_errors = self._validate_step(step, defined_outputs, f"{context}.steps[{i}]")
            errors.extend(step_errors)

        return errors

    def _extract_template_references(self, data: Any) -> list[str]:
        """Extract all template variable references from data."""
        refs: list[str] = []

        if isinstance(data, str):
            matches = self.TEMPLATE_PATTERN.findall(data)
            refs.extend(matches)
        elif isinstance(data, dict):
            for value in data.values():
                refs.extend(self._extract_template_references(value))
        elif isinstance(data, list):
            for item in data:
                refs.extend(self._extract_template_references(item))

        return refs
