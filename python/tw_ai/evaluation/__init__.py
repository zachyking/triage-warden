"""Evaluation framework for Triage Warden AI agents.

This module provides tools for:
- Loading test cases from YAML files
- Running evaluations on agent implementations
- Calculating metrics (accuracy, precision, recall, F1)
- Generating evaluation reports

Usage:
    from tw_ai.evaluation import EvaluationRunner, load_test_cases

    cases = load_test_cases("path/to/test_cases/")
    runner = EvaluationRunner(agent=agent)
    report = await runner.evaluate(cases)
    print(report.accuracy, report.f1_score)
"""

from tw_ai.evaluation.dataset import TestCase, load_test_cases
from tw_ai.evaluation.metrics import (
    EvaluationReport,
    calculate_severity_accuracy,
    calculate_verdict_metrics,
    generate_confusion_matrix,
)
from tw_ai.evaluation.runner import EvaluationConfig, EvaluationRunner

__all__ = [
    # Dataset
    "TestCase",
    "load_test_cases",
    # Runner
    "EvaluationRunner",
    "EvaluationConfig",
    # Metrics
    "EvaluationReport",
    "calculate_verdict_metrics",
    "calculate_severity_accuracy",
    "generate_confusion_matrix",
]
