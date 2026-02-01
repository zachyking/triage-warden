"""Evaluation runner for executing test cases against agents.

This module provides:
- EvaluationRunner class for running evaluations
- Support for different LLM providers
- Parallel execution support
- Result collection and aggregation
"""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

import structlog

from tw_ai.evaluation.dataset import TestCase
from tw_ai.evaluation.metrics import (
    EvaluationReport,
    VerdictMetrics,
    calculate_severity_accuracy,
    calculate_technique_recall,
    calculate_verdict_metrics,
    generate_confusion_matrix,
)

logger = structlog.get_logger()


@runtime_checkable
class EvaluatableAgent(Protocol):
    """Protocol for agents that can be evaluated.

    Agents must implement an async run() method that accepts alert data
    and returns results with verdict, severity, and techniques.
    """

    async def run(self, request: Any) -> Any:
        """Run the agent on a request."""
        ...


@dataclass
class EvaluationConfig:
    """Configuration for evaluation runs.

    Attributes:
        max_concurrent: Maximum concurrent evaluations
        timeout_per_case: Timeout in seconds per test case
        retry_failed: Whether to retry failed cases
        max_retries: Maximum retries for failed cases
        verbose: Whether to log detailed progress
    """

    max_concurrent: int = 5
    timeout_per_case: float = 120.0
    retry_failed: bool = True
    max_retries: int = 2
    verbose: bool = True


@dataclass
class CaseResult:
    """Result from evaluating a single test case.

    Attributes:
        test_case_id: ID of the test case
        test_case_name: Name of the test case
        passed: Whether the verdict matched
        predicted_verdict: Agent's predicted verdict
        expected_verdict: Ground truth verdict
        predicted_severity: Agent's predicted severity
        expected_severity: Ground truth severity
        predicted_techniques: Agent's predicted MITRE techniques
        expected_techniques: Ground truth techniques
        execution_time: Time taken to run the case
        error: Error message if case failed to execute
        raw_output: Raw agent output for debugging
    """

    test_case_id: str
    test_case_name: str
    passed: bool
    predicted_verdict: str | None = None
    expected_verdict: str | None = None
    predicted_severity: str | None = None
    expected_severity: str | None = None
    predicted_techniques: list[str] = field(default_factory=list)
    expected_techniques: list[str] = field(default_factory=list)
    execution_time: float = 0.0
    error: str | None = None
    raw_output: Any = None

    def to_dict(self) -> dict[str, Any]:
        """Convert result to dictionary."""
        return {
            "test_case_id": self.test_case_id,
            "test_case_name": self.test_case_name,
            "passed": self.passed,
            "predicted_verdict": self.predicted_verdict,
            "expected_verdict": self.expected_verdict,
            "predicted_severity": self.predicted_severity,
            "expected_severity": self.expected_severity,
            "predicted_techniques": self.predicted_techniques,
            "expected_techniques": self.expected_techniques,
            "execution_time": self.execution_time,
            "error": self.error,
        }


class EvaluationRunner:
    """Runner for executing evaluation test cases against an agent.

    The runner handles:
    - Sequential or parallel test case execution
    - Timeout handling
    - Result collection and aggregation
    - Metric calculation

    Example:
        runner = EvaluationRunner(agent=my_agent)
        report = await runner.evaluate(test_cases)
        print(report.accuracy, report.f1_score)
    """

    def __init__(
        self,
        agent: EvaluatableAgent,
        config: EvaluationConfig | None = None,
    ):
        """Initialize the evaluation runner.

        Args:
            agent: Agent instance implementing the EvaluatableAgent protocol
            config: Evaluation configuration (uses defaults if not provided)
        """
        self.agent = agent
        self.config = config or EvaluationConfig()

        logger.info(
            "evaluation_runner_initialized",
            max_concurrent=self.config.max_concurrent,
            timeout_per_case=self.config.timeout_per_case,
        )

    async def evaluate(
        self,
        cases: list[TestCase],
        parallel: bool = False,
    ) -> EvaluationReport:
        """Evaluate the agent on a set of test cases.

        Args:
            cases: List of test cases to evaluate
            parallel: Whether to run cases in parallel

        Returns:
            EvaluationReport with all metrics
        """
        if not cases:
            return self._create_empty_report()

        logger.info(
            "evaluation_started",
            total_cases=len(cases),
            parallel=parallel,
        )

        start_time = time.time()

        if parallel:
            results = await self._run_parallel(cases)
        else:
            results = await self._run_sequential(cases)

        total_time = time.time() - start_time

        # Calculate metrics
        report = self._calculate_report(results, total_time)

        logger.info(
            "evaluation_completed",
            total_cases=len(cases),
            passed=report.passed_cases,
            failed=report.failed_cases,
            accuracy=report.accuracy,
            f1_score=report.f1_score,
            total_time=total_time,
        )

        return report

    async def _run_sequential(self, cases: list[TestCase]) -> list[CaseResult]:
        """Run test cases sequentially."""
        results = []

        for i, case in enumerate(cases):
            if self.config.verbose:
                logger.info(
                    "evaluating_case",
                    case_id=case.id,
                    case_name=case.name,
                    progress=f"{i + 1}/{len(cases)}",
                )

            result = await self._evaluate_single_case(case)
            results.append(result)

        return results

    async def _run_parallel(self, cases: list[TestCase]) -> list[CaseResult]:
        """Run test cases in parallel with concurrency limit."""
        semaphore = asyncio.Semaphore(self.config.max_concurrent)

        async def limited_evaluate(case: TestCase) -> CaseResult:
            async with semaphore:
                return await self._evaluate_single_case(case)

        tasks = [limited_evaluate(case) for case in cases]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Convert exceptions to CaseResult
        processed_results: list[CaseResult] = []
        for case, result in zip(cases, results):
            if isinstance(result, BaseException):
                processed_results.append(
                    CaseResult(
                        test_case_id=case.id,
                        test_case_name=case.name,
                        passed=False,
                        expected_verdict=case.expected_verdict,
                        expected_severity=case.expected_severity,
                        expected_techniques=case.expected_techniques,
                        error=str(result),
                    )
                )
            else:
                processed_results.append(result)

        return processed_results

    async def _evaluate_single_case(
        self,
        case: TestCase,
        retry_count: int = 0,
    ) -> CaseResult:
        """Evaluate a single test case.

        Args:
            case: The test case to evaluate
            retry_count: Current retry attempt

        Returns:
            CaseResult with evaluation outcome
        """
        start_time = time.time()

        try:
            # Build request from alert data
            request = self._build_request(case)

            # Run with timeout
            result = await asyncio.wait_for(
                self.agent.run(request),
                timeout=self.config.timeout_per_case,
            )

            execution_time = time.time() - start_time

            # Extract predictions from result
            predicted_verdict = self._extract_verdict(result)
            predicted_severity = self._extract_severity(result)
            predicted_techniques = self._extract_techniques(result)

            # Determine if passed (verdict match)
            passed = self._normalize_verdict(predicted_verdict) == self._normalize_verdict(
                case.expected_verdict
            )

            return CaseResult(
                test_case_id=case.id,
                test_case_name=case.name,
                passed=passed,
                predicted_verdict=predicted_verdict,
                expected_verdict=case.expected_verdict,
                predicted_severity=predicted_severity,
                expected_severity=case.expected_severity,
                predicted_techniques=predicted_techniques,
                expected_techniques=case.expected_techniques,
                execution_time=execution_time,
                raw_output=result,
            )

        except asyncio.TimeoutError:
            logger.warning(
                "case_timeout",
                case_id=case.id,
                timeout=self.config.timeout_per_case,
            )
            return CaseResult(
                test_case_id=case.id,
                test_case_name=case.name,
                passed=False,
                expected_verdict=case.expected_verdict,
                expected_severity=case.expected_severity,
                expected_techniques=case.expected_techniques,
                execution_time=time.time() - start_time,
                error=f"Timeout after {self.config.timeout_per_case}s",
            )

        except Exception as e:
            logger.error(
                "case_error",
                case_id=case.id,
                error=str(e),
                exc_info=True,
            )

            # Retry if configured
            if self.config.retry_failed and retry_count < self.config.max_retries:
                logger.info(
                    "retrying_case",
                    case_id=case.id,
                    retry=retry_count + 1,
                    max_retries=self.config.max_retries,
                )
                return await self._evaluate_single_case(case, retry_count + 1)

            return CaseResult(
                test_case_id=case.id,
                test_case_name=case.name,
                passed=False,
                expected_verdict=case.expected_verdict,
                expected_severity=case.expected_severity,
                expected_techniques=case.expected_techniques,
                execution_time=time.time() - start_time,
                error=str(e),
            )

    def _build_request(self, case: TestCase) -> Any:
        """Build an agent request from a test case.

        Attempts to use TriageRequest if available, otherwise returns dict.
        """
        try:
            from tw_ai.agents.react import TriageRequest

            # Infer alert type from category or alert data
            alert_type = case.category or case.alert_data.get("type", "security_alert")

            return TriageRequest(
                alert_type=alert_type,
                alert_data=case.alert_data,
            )
        except ImportError:
            # Fall back to dict-based request
            return case.alert_data

    def _extract_verdict(self, result: Any) -> str | None:
        """Extract verdict from agent result."""
        # Handle AgentResult with analysis
        if hasattr(result, "analysis") and result.analysis:
            verdict = getattr(result.analysis, "verdict", None)
            if verdict:
                return self._normalize_verdict(verdict)

        # Handle dict-like results
        if isinstance(result, dict):
            return self._normalize_verdict(result.get("verdict"))

        # Handle result with direct verdict attribute
        if hasattr(result, "verdict"):
            return self._normalize_verdict(result.verdict)

        return None

    def _extract_severity(self, result: Any) -> str | None:
        """Extract severity from agent result."""
        if hasattr(result, "analysis") and result.analysis:
            return getattr(result.analysis, "severity", None)

        if isinstance(result, dict):
            return result.get("severity")

        if hasattr(result, "severity"):
            severity: str | None = getattr(result, "severity", None)
            return severity

        return None

    def _extract_techniques(self, result: Any) -> list[str]:
        """Extract MITRE technique IDs from agent result."""
        techniques = []

        if hasattr(result, "analysis") and result.analysis:
            mitre_techniques = getattr(result.analysis, "mitre_techniques", [])
            for tech in mitre_techniques:
                if hasattr(tech, "id"):
                    techniques.append(tech.id)
                elif isinstance(tech, dict):
                    techniques.append(tech.get("id", ""))

        elif isinstance(result, dict):
            mitre_techniques = result.get("mitre_techniques", [])
            for tech in mitre_techniques:
                if isinstance(tech, dict):
                    techniques.append(tech.get("id", ""))
                elif isinstance(tech, str):
                    techniques.append(tech)

        return [t for t in techniques if t]

    def _normalize_verdict(self, verdict: str | None) -> str | None:
        """Normalize verdict to standard format.

        Maps agent verdicts to evaluation verdicts:
        - true_positive, malicious -> malicious
        - false_positive, benign -> benign
        - suspicious -> suspicious
        """
        if verdict is None:
            return None

        verdict_lower = verdict.lower().strip()

        # Map true_positive to malicious (it's a real threat)
        if verdict_lower in ("true_positive", "malicious"):
            return "malicious"

        # Map false_positive to benign (not a real threat)
        if verdict_lower in ("false_positive", "benign"):
            return "benign"

        # Keep suspicious as-is
        if verdict_lower in ("suspicious", "inconclusive"):
            return "suspicious"

        return verdict_lower

    def _calculate_report(
        self,
        results: list[CaseResult],
        total_time: float,
    ) -> EvaluationReport:
        """Calculate evaluation report from case results."""
        # Filter out cases with errors for metric calculation
        valid_results = [r for r in results if r.error is None and r.predicted_verdict]

        # Extract predictions and labels
        predictions = [r.predicted_verdict for r in valid_results if r.predicted_verdict]
        labels = [r.expected_verdict for r in valid_results if r.expected_verdict]

        # Calculate verdict metrics
        if predictions and labels:
            verdict_metrics = calculate_verdict_metrics(predictions, labels)
        else:
            verdict_metrics = VerdictMetrics(accuracy=0.0, precision=0.0, recall=0.0, f1_score=0.0)

        # Calculate severity accuracy
        severity_predictions = [r.predicted_severity for r in valid_results]
        severity_labels = [r.expected_severity for r in valid_results]
        severity_accuracy = calculate_severity_accuracy(severity_predictions, severity_labels)

        # Generate confusion matrix
        if predictions and labels:
            confusion_matrix = generate_confusion_matrix(predictions, labels)
        else:
            confusion_matrix = {}

        # Calculate technique recall
        technique_predictions = [r.predicted_techniques for r in valid_results]
        technique_labels = [r.expected_techniques for r in valid_results]
        technique_recall = calculate_technique_recall(technique_predictions, technique_labels)

        # Count passed/failed
        passed = sum(1 for r in results if r.passed)
        failed = len(results) - passed

        # Average execution time
        total_exec_time = sum(r.execution_time for r in results)
        avg_exec_time = total_exec_time / len(results) if results else 0.0

        return EvaluationReport(
            total_cases=len(results),
            passed_cases=passed,
            failed_cases=failed,
            accuracy=verdict_metrics.accuracy,
            precision=verdict_metrics.precision,
            recall=verdict_metrics.recall,
            f1_score=verdict_metrics.f1_score,
            severity_accuracy=severity_accuracy,
            confusion_matrix=confusion_matrix,
            verdict_metrics=verdict_metrics,
            technique_recall=technique_recall,
            avg_execution_time=avg_exec_time,
            results=[r.to_dict() for r in results],
        )

    def _create_empty_report(self) -> EvaluationReport:
        """Create an empty evaluation report."""
        return EvaluationReport(
            total_cases=0,
            passed_cases=0,
            failed_cases=0,
            accuracy=0.0,
            precision=0.0,
            recall=0.0,
            f1_score=0.0,
            severity_accuracy=0.0,
            confusion_matrix={},
            technique_recall=0.0,
            avg_execution_time=0.0,
            results=[],
        )

    def save_report(self, report: EvaluationReport, path: str) -> None:
        """Save evaluation report to JSON file.

        Args:
            report: Report to save
            path: Output file path
        """
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report.to_dict(), f, indent=2)

        logger.info("report_saved", path=path)
