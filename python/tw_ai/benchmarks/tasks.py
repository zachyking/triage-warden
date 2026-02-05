"""Security task definitions for benchmark evaluation.

Each task class defines:
- How to format prompts for the LLM
- How to parse LLM outputs
- Task-specific evaluation logic
"""

from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from tw_ai.benchmarks.datasets import BenchmarkExample, TaskType


@runtime_checkable
class LLMProvider(Protocol):
    """Protocol for LLM providers used in benchmarks."""

    async def complete(self, prompt: str) -> str:
        """Generate a completion for the given prompt."""
        ...


@dataclass
class TaskResult:
    """Result from evaluating a single benchmark example.

    Attributes:
        example_id: ID of the benchmark example
        task_type: Type of security task
        predicted: Model's predicted output
        expected: Ground truth expected output
        scores: Dictionary of metric scores
        raw_output: Raw model output before parsing
        error: Error message if evaluation failed
    """

    example_id: str
    task_type: TaskType
    predicted: dict[str, Any]
    expected: dict[str, Any]
    scores: dict[str, float] = field(default_factory=dict)
    raw_output: str = ""
    error: str | None = None

    @property
    def passed(self) -> bool:
        """Check if the task passed based on primary metric."""
        if self.error:
            return False
        primary_score = self.scores.get("primary", 0.0)
        return primary_score >= 0.5  # Default threshold


class BaseSecurityTask(ABC):
    """Base class for security benchmark tasks.

    Each task defines how to:
    1. Generate prompts for the LLM
    2. Parse LLM outputs into structured data
    3. Evaluate predictions against ground truth
    """

    task_type: TaskType
    name: str
    description: str

    @abstractmethod
    def format_prompt(self, example: BenchmarkExample) -> str:
        """Format the input data into a prompt for the LLM.

        Args:
            example: The benchmark example to format

        Returns:
            Formatted prompt string
        """
        pass

    @abstractmethod
    def parse_output(self, raw_output: str) -> dict[str, Any]:
        """Parse the LLM's raw output into structured data.

        Args:
            raw_output: Raw text output from the LLM

        Returns:
            Parsed structured output
        """
        pass

    @abstractmethod
    def evaluate(self, predicted: dict[str, Any], expected: dict[str, Any]) -> dict[str, float]:
        """Evaluate predicted output against expected.

        Args:
            predicted: Parsed model output
            expected: Ground truth expected output

        Returns:
            Dictionary of metric name to score
        """
        pass

    async def run(self, example: BenchmarkExample, llm: LLMProvider) -> TaskResult:
        """Run the task on a single example.

        Args:
            example: The benchmark example to evaluate
            llm: LLM provider for generating completions

        Returns:
            TaskResult with scores and metadata
        """
        try:
            prompt = self.format_prompt(example)
            raw_output = await llm.complete(prompt)
            predicted = self.parse_output(raw_output)
            scores = self.evaluate(predicted, example.expected_output)

            return TaskResult(
                example_id=example.id,
                task_type=self.task_type,
                predicted=predicted,
                expected=example.expected_output,
                scores=scores,
                raw_output=raw_output,
            )

        except Exception as e:
            return TaskResult(
                example_id=example.id,
                task_type=self.task_type,
                predicted={},
                expected=example.expected_output,
                error=str(e),
            )


class VerdictClassificationTask(BaseSecurityTask):
    """Task for classifying security alerts as true/false positive."""

    task_type = TaskType.VERDICT_CLASSIFICATION
    name = "Verdict Classification"
    description = "Classify security alerts as true_positive, false_positive, or suspicious"

    VALID_VERDICTS = {"true_positive", "false_positive", "suspicious", "inconclusive"}

    def format_prompt(self, example: BenchmarkExample) -> str:
        """Format alert data into a classification prompt."""
        alert_data = json.dumps(example.input_data, indent=2)

        return f"""You are a security analyst. Analyze the following security alert and classify it.

ALERT DATA:
{alert_data}

Provide your analysis in the following JSON format:
{{
    "verdict": "<true_positive|false_positive|suspicious|inconclusive>",
    "confidence": <0-100>,
    "reasoning": "<brief explanation>"
}}

Respond only with the JSON object, no additional text."""

    def parse_output(self, raw_output: str) -> dict[str, Any]:
        """Parse verdict classification output."""
        # Try to extract JSON from the output
        try:
            # Handle markdown code blocks
            if "```json" in raw_output:
                match = re.search(r"```json\s*(.*?)\s*```", raw_output, re.DOTALL)
                if match:
                    raw_output = match.group(1)
            elif "```" in raw_output:
                match = re.search(r"```\s*(.*?)\s*```", raw_output, re.DOTALL)
                if match:
                    raw_output = match.group(1)

            data = json.loads(raw_output.strip())

            # Normalize verdict
            verdict = data.get("verdict", "").lower().strip()
            if verdict not in self.VALID_VERDICTS:
                verdict = "inconclusive"

            return {
                "verdict": verdict,
                "confidence": int(data.get("confidence", 50)),
                "reasoning": data.get("reasoning", ""),
            }

        except (json.JSONDecodeError, TypeError, ValueError):
            # Fallback: try to extract verdict from text
            text = raw_output.lower()
            if "true_positive" in text or "true positive" in text:
                return {"verdict": "true_positive", "confidence": 50}
            elif "false_positive" in text or "false positive" in text:
                return {"verdict": "false_positive", "confidence": 50}
            elif "suspicious" in text:
                return {"verdict": "suspicious", "confidence": 50}
            return {"verdict": "inconclusive", "confidence": 0}

    def evaluate(self, predicted: dict[str, Any], expected: dict[str, Any]) -> dict[str, float]:
        """Evaluate verdict prediction."""
        pred_verdict = predicted.get("verdict", "").lower()
        exp_verdict = expected.get("verdict", "").lower()

        # Exact match for verdict
        verdict_match = 1.0 if pred_verdict == exp_verdict else 0.0

        # Confidence calibration (how close is predicted confidence to expected)
        pred_conf = predicted.get("confidence", 50)
        exp_conf = expected.get("confidence", 50)
        conf_error = abs(pred_conf - exp_conf) / 100
        conf_score = 1.0 - conf_error

        return {
            "primary": verdict_match,
            "verdict_accuracy": verdict_match,
            "confidence_calibration": conf_score,
        }


class SeverityRatingTask(BaseSecurityTask):
    """Task for rating incident severity levels."""

    task_type = TaskType.SEVERITY_RATING
    name = "Severity Rating"
    description = "Rate incident severity as critical, high, medium, low, or informational"

    VALID_SEVERITIES = {"critical", "high", "medium", "low", "informational"}
    SEVERITY_ORDER = ["informational", "low", "medium", "high", "critical"]

    def format_prompt(self, example: BenchmarkExample) -> str:
        """Format incident data into a severity rating prompt."""
        incident_data = json.dumps(example.input_data, indent=2)

        return f"""You are a security analyst. Rate the severity of the following security incident.

INCIDENT DATA:
{incident_data}

Severity levels (from lowest to highest):
- informational: No security impact
- low: Minor security concern, low risk
- medium: Moderate security risk, requires attention
- high: Significant security risk, requires prompt action
- critical: Severe security incident, immediate action required

Provide your rating in the following JSON format:
{{
    "severity": "<critical|high|medium|low|informational>",
    "justification": "<brief explanation for the rating>"
}}

Respond only with the JSON object, no additional text."""

    def parse_output(self, raw_output: str) -> dict[str, Any]:
        """Parse severity rating output."""
        try:
            # Handle markdown code blocks
            if "```json" in raw_output:
                match = re.search(r"```json\s*(.*?)\s*```", raw_output, re.DOTALL)
                if match:
                    raw_output = match.group(1)
            elif "```" in raw_output:
                match = re.search(r"```\s*(.*?)\s*```", raw_output, re.DOTALL)
                if match:
                    raw_output = match.group(1)

            data = json.loads(raw_output.strip())

            severity = data.get("severity", "").lower().strip()
            if severity not in self.VALID_SEVERITIES:
                severity = "medium"

            return {
                "severity": severity,
                "justification": data.get("justification", ""),
            }

        except (json.JSONDecodeError, TypeError, ValueError):
            # Fallback: try to extract severity from text
            text = raw_output.lower()
            for sev in self.SEVERITY_ORDER[::-1]:  # Check from critical down
                if sev in text:
                    return {"severity": sev, "justification": ""}
            return {"severity": "medium", "justification": ""}

    def evaluate(self, predicted: dict[str, Any], expected: dict[str, Any]) -> dict[str, float]:
        """Evaluate severity rating."""
        pred_sev = predicted.get("severity", "medium").lower()
        exp_sev = expected.get("severity", "medium").lower()

        # Exact match
        exact_match = 1.0 if pred_sev == exp_sev else 0.0

        # Distance-based score (penalize by how far off the rating is)
        pred_idx = self.SEVERITY_ORDER.index(pred_sev) if pred_sev in self.SEVERITY_ORDER else 2
        exp_idx = self.SEVERITY_ORDER.index(exp_sev) if exp_sev in self.SEVERITY_ORDER else 2
        distance = abs(pred_idx - exp_idx)
        distance_score = max(0, 1.0 - (distance * 0.25))  # 25% penalty per level

        return {
            "primary": exact_match,
            "exact_match": exact_match,
            "distance_score": distance_score,
        }


class MitreMappingTask(BaseSecurityTask):
    """Task for mapping attack behaviors to MITRE ATT&CK techniques."""

    task_type = TaskType.MITRE_MAPPING
    name = "MITRE ATT&CK Mapping"
    description = "Map observed attack behaviors to MITRE ATT&CK techniques"

    MITRE_ID_PATTERN = re.compile(r"T\d{4}(?:\.\d{1,3})?")

    def format_prompt(self, example: BenchmarkExample) -> str:
        """Format attack description into a MITRE mapping prompt."""
        description = example.input_data.get("description", "")
        indicators = example.input_data.get("indicators", [])
        indicators_text = "\n".join(f"  - {ind}" for ind in indicators)

        return f"""You are a threat intelligence analyst. Map the following attack behavior to MITRE ATT&CK techniques.

ATTACK DESCRIPTION:
{description}

OBSERVED INDICATORS:
{indicators_text}

Provide your mapping in the following JSON format:
{{
    "techniques": [
        {{
            "id": "<MITRE technique ID, e.g., T1566.001>",
            "name": "<Technique name>",
            "tactic": "<Associated tactic>"
        }}
    ]
}}

Include all relevant techniques. Respond only with the JSON object, no additional text."""

    def parse_output(self, raw_output: str) -> dict[str, Any]:
        """Parse MITRE mapping output."""
        try:
            # Handle markdown code blocks
            if "```json" in raw_output:
                match = re.search(r"```json\s*(.*?)\s*```", raw_output, re.DOTALL)
                if match:
                    raw_output = match.group(1)
            elif "```" in raw_output:
                match = re.search(r"```\s*(.*?)\s*```", raw_output, re.DOTALL)
                if match:
                    raw_output = match.group(1)

            data = json.loads(raw_output.strip())

            techniques = []
            for tech in data.get("techniques", []):
                tech_id = tech.get("id", "")
                if self.MITRE_ID_PATTERN.match(tech_id):
                    techniques.append(
                        {
                            "id": tech_id,
                            "name": tech.get("name", ""),
                            "tactic": tech.get("tactic", ""),
                        }
                    )

            return {"techniques": techniques}

        except (json.JSONDecodeError, TypeError, ValueError):
            # Fallback: try to extract technique IDs from text
            tech_ids = self.MITRE_ID_PATTERN.findall(raw_output)
            return {"techniques": [{"id": tid, "name": "", "tactic": ""} for tid in tech_ids]}

    def evaluate(self, predicted: dict[str, Any], expected: dict[str, Any]) -> dict[str, float]:
        """Evaluate MITRE technique mapping."""
        pred_techniques = {t["id"] for t in predicted.get("techniques", [])}
        exp_techniques = {t["id"] for t in expected.get("techniques", [])}

        if not exp_techniques:
            # No expected techniques, check for correct empty prediction
            return {"primary": 1.0 if not pred_techniques else 0.0}

        # Calculate precision, recall, F1
        true_positives = len(pred_techniques & exp_techniques)

        precision = true_positives / len(pred_techniques) if pred_techniques else 0.0
        recall = true_positives / len(exp_techniques)
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

        return {
            "primary": f1,
            "precision": precision,
            "recall": recall,
            "f1": f1,
        }


class IncidentSummarizationTask(BaseSecurityTask):
    """Task for generating incident summaries."""

    task_type = TaskType.INCIDENT_SUMMARIZATION
    name = "Incident Summarization"
    description = "Generate concise summaries of security incidents"

    def format_prompt(self, example: BenchmarkExample) -> str:
        """Format incident data into a summarization prompt."""
        incident_data = json.dumps(example.input_data, indent=2)

        return f"""You are a security analyst. Summarize the following security incident for a report.

INCIDENT DATA:
{incident_data}

Provide your summary in the following JSON format:
{{
    "summary": "<2-3 sentence summary of the incident>",
    "key_findings": ["<finding 1>", "<finding 2>", ...]
}}

Be concise but include all critical information. Respond only with the JSON object."""

    def parse_output(self, raw_output: str) -> dict[str, Any]:
        """Parse summarization output."""
        try:
            # Handle markdown code blocks
            if "```json" in raw_output:
                match = re.search(r"```json\s*(.*?)\s*```", raw_output, re.DOTALL)
                if match:
                    raw_output = match.group(1)
            elif "```" in raw_output:
                match = re.search(r"```\s*(.*?)\s*```", raw_output, re.DOTALL)
                if match:
                    raw_output = match.group(1)

            data = json.loads(raw_output.strip())

            return {
                "summary": data.get("summary", ""),
                "key_findings": data.get("key_findings", []),
            }

        except (json.JSONDecodeError, TypeError, ValueError):
            # Use raw output as summary
            return {"summary": raw_output.strip(), "key_findings": []}

    def evaluate(self, predicted: dict[str, Any], expected: dict[str, Any]) -> dict[str, float]:
        """Evaluate incident summarization.

        Uses simple heuristics for evaluation:
        - Key findings coverage
        - Summary length appropriateness
        """
        pred_summary = predicted.get("summary", "").lower()
        pred_findings = [f.lower() for f in predicted.get("key_findings", [])]
        exp_findings = [f.lower() for f in expected.get("key_findings", [])]

        # Check how many expected findings are mentioned
        findings_covered = 0
        for exp_finding in exp_findings:
            # Check if key words from expected finding appear in summary or predicted findings
            exp_words = set(exp_finding.split())
            summary_words = set(pred_summary.split())
            pred_words = set(" ".join(pred_findings).split())
            all_pred_words = summary_words | pred_words

            # If >50% of words match, count as covered
            overlap = len(exp_words & all_pred_words)
            if overlap >= len(exp_words) * 0.5:
                findings_covered += 1

        findings_score = findings_covered / len(exp_findings) if exp_findings else 0.0

        # Summary length check (should be meaningful but concise)
        summary_len = len(pred_summary.split())
        length_score = 1.0 if 20 <= summary_len <= 100 else max(0, 1 - abs(summary_len - 60) / 60)

        # Combined score
        primary = (findings_score * 0.7) + (length_score * 0.3)

        return {
            "primary": primary,
            "findings_coverage": findings_score,
            "length_appropriateness": length_score,
        }


class ActionRecommendationTask(BaseSecurityTask):
    """Task for recommending incident response actions."""

    task_type = TaskType.ACTION_RECOMMENDATION
    name = "Action Recommendation"
    description = "Recommend appropriate response actions for security incidents"

    PRIORITY_ORDER = ["immediate", "high", "medium", "low"]

    def format_prompt(self, example: BenchmarkExample) -> str:
        """Format incident data into an action recommendation prompt."""
        incident_data = json.dumps(example.input_data, indent=2)

        return f"""You are a security incident responder. Recommend response actions for the following incident.

INCIDENT DATA:
{incident_data}

Provide your recommendations in the following JSON format:
{{
    "actions": [
        {{
            "action": "<description of the action>",
            "priority": "<immediate|high|medium|low>"
        }}
    ]
}}

Order actions by priority. Include all necessary response steps. Respond only with the JSON object."""

    def parse_output(self, raw_output: str) -> dict[str, Any]:
        """Parse action recommendation output."""
        try:
            # Handle markdown code blocks
            if "```json" in raw_output:
                match = re.search(r"```json\s*(.*?)\s*```", raw_output, re.DOTALL)
                if match:
                    raw_output = match.group(1)
            elif "```" in raw_output:
                match = re.search(r"```\s*(.*?)\s*```", raw_output, re.DOTALL)
                if match:
                    raw_output = match.group(1)

            data = json.loads(raw_output.strip())

            actions = []
            for act in data.get("actions", []):
                priority = act.get("priority", "medium").lower()
                if priority not in self.PRIORITY_ORDER:
                    priority = "medium"
                actions.append(
                    {
                        "action": act.get("action", ""),
                        "priority": priority,
                    }
                )

            return {"actions": actions}

        except (json.JSONDecodeError, TypeError, ValueError):
            return {"actions": []}

    def evaluate(self, predicted: dict[str, Any], expected: dict[str, Any]) -> dict[str, float]:
        """Evaluate action recommendations."""
        pred_actions = predicted.get("actions", [])
        exp_actions = expected.get("actions", [])

        if not exp_actions:
            return {"primary": 1.0 if not pred_actions else 0.5}

        # Check coverage of expected actions (using keyword matching)
        exp_action_keywords = [set(a["action"].lower().split()) for a in exp_actions]
        pred_action_keywords = [set(a["action"].lower().split()) for a in pred_actions]

        actions_covered = 0
        for exp_keywords in exp_action_keywords:
            for pred_keywords in pred_action_keywords:
                # If significant overlap, count as match
                overlap = len(exp_keywords & pred_keywords)
                if overlap >= min(3, len(exp_keywords) * 0.5):
                    actions_covered += 1
                    break

        coverage_score = actions_covered / len(exp_actions) if exp_actions else 0.0

        # Check priority ordering (immediate actions should come first)
        priority_score = 1.0
        if pred_actions:
            for i, action in enumerate(pred_actions):
                priority = action.get("priority", "medium")
                expected_priority_idx = self.PRIORITY_ORDER.index(priority)
                # Early actions should have high priority (low index)
                if i == 0 and expected_priority_idx > 1:  # First action not immediate/high
                    priority_score -= 0.2
                if i > 0 and expected_priority_idx == 0:  # immediate action not first
                    priority_score -= 0.1

        priority_score = max(0, priority_score)

        primary = (coverage_score * 0.7) + (priority_score * 0.3)

        return {
            "primary": primary,
            "action_coverage": coverage_score,
            "priority_ordering": priority_score,
        }


class IoCQueryGenerationTask(BaseSecurityTask):
    """Task for generating IoC search queries."""

    task_type = TaskType.IOC_QUERY_GENERATION
    name = "IoC Query Generation"
    description = "Generate SIEM queries to search for indicators of compromise"

    def format_prompt(self, example: BenchmarkExample) -> str:
        """Format IoC data into a query generation prompt."""
        ioc_type = example.input_data.get("ioc_type", "unknown")
        ioc_value = example.input_data.get("ioc_value", "")
        query_target = example.input_data.get("query_target", "splunk")
        time_range = example.input_data.get("time_range", "last_7_days")

        return f"""You are a security analyst. Generate a search query for the following indicator of compromise.

IOC TYPE: {ioc_type}
IOC VALUE: {ioc_value}
TARGET SYSTEM: {query_target}
TIME RANGE: {time_range}

Provide your query in the following JSON format:
{{
    "query": "<the search query>",
    "description": "<brief description of what the query searches for>"
}}

Generate a valid query for the target system. Respond only with the JSON object."""

    def parse_output(self, raw_output: str) -> dict[str, Any]:
        """Parse query generation output."""
        try:
            # Handle markdown code blocks
            if "```json" in raw_output:
                match = re.search(r"```json\s*(.*?)\s*```", raw_output, re.DOTALL)
                if match:
                    raw_output = match.group(1)
            elif "```" in raw_output:
                match = re.search(r"```\s*(.*?)\s*```", raw_output, re.DOTALL)
                if match:
                    raw_output = match.group(1)

            data = json.loads(raw_output.strip())

            return {
                "query": data.get("query", ""),
                "description": data.get("description", ""),
            }

        except (json.JSONDecodeError, TypeError, ValueError):
            return {"query": raw_output.strip(), "description": ""}

    def evaluate(self, predicted: dict[str, Any], expected: dict[str, Any]) -> dict[str, float]:
        """Evaluate IoC query generation.

        Checks:
        - Whether the IoC value is in the query
        - Basic syntax validity
        - Query completeness
        """
        pred_query = predicted.get("query", "").lower()
        exp_query = expected.get("query", "").lower()

        if not pred_query:
            return {"primary": 0.0, "query_valid": 0.0}

        # Check if IoC appears in query (basic requirement)
        ioc_present = 0.0
        # Extract potential IoC from expected query
        ioc_patterns = re.findall(r'["\']([^"\']+)["\']|=(\S+)', exp_query)
        for match in ioc_patterns:
            ioc = match[0] or match[1]
            if ioc and len(ioc) > 3 and ioc in pred_query:
                ioc_present = 1.0
                break

        # Check for basic query structure
        has_structure = 0.0
        structure_keywords = ["index", "select", "search", "where", "event", "src", "dest", "query"]
        for keyword in structure_keywords:
            if keyword in pred_query:
                has_structure = 0.5
                break

        if "=" in pred_query or ":" in pred_query:
            has_structure = 1.0

        # Partial query similarity
        pred_words = set(pred_query.split())
        exp_words = set(exp_query.split())
        if exp_words:
            word_overlap = len(pred_words & exp_words) / len(exp_words)
        else:
            word_overlap = 0.0

        primary = (ioc_present * 0.4) + (has_structure * 0.3) + (word_overlap * 0.3)

        return {
            "primary": primary,
            "ioc_present": ioc_present,
            "has_valid_structure": has_structure,
            "word_overlap": word_overlap,
        }


# Task registry for easy lookup
TASK_REGISTRY: dict[TaskType, type[BaseSecurityTask]] = {
    TaskType.VERDICT_CLASSIFICATION: VerdictClassificationTask,
    TaskType.SEVERITY_RATING: SeverityRatingTask,
    TaskType.MITRE_MAPPING: MitreMappingTask,
    TaskType.INCIDENT_SUMMARIZATION: IncidentSummarizationTask,
    TaskType.ACTION_RECOMMENDATION: ActionRecommendationTask,
    TaskType.IOC_QUERY_GENERATION: IoCQueryGenerationTask,
}


def get_task(task_type: TaskType) -> BaseSecurityTask:
    """Get a task instance by type.

    Args:
        task_type: The type of task to get

    Returns:
        Instance of the task class

    Raises:
        ValueError: If task type is not registered
    """
    task_class = TASK_REGISTRY.get(task_type)
    if not task_class:
        raise ValueError(f"Unknown task type: {task_type}")
    return task_class()
