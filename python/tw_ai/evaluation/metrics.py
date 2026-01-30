"""Evaluation metrics calculation for agent performance assessment.

This module provides:
- Verdict metrics (accuracy, precision, recall, F1)
- Severity accuracy calculation
- Confusion matrix generation
- EvaluationReport dataclass for comprehensive results
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

# Type aliases for clarity
Verdict = Literal["malicious", "benign", "suspicious"]
Severity = Literal["critical", "high", "medium", "low", "informational"]


@dataclass
class VerdictMetrics:
    """Metrics for verdict classification.

    Attributes:
        accuracy: Overall accuracy (correct / total)
        precision: Precision for malicious class
        recall: Recall for malicious class
        f1_score: F1 score for malicious class
        per_class_metrics: Metrics broken down by class
    """

    accuracy: float
    precision: float
    recall: float
    f1_score: float
    per_class_metrics: dict[str, dict[str, float]] = field(default_factory=dict)


@dataclass
class EvaluationReport:
    """Complete evaluation report with all metrics.

    Attributes:
        total_cases: Total number of test cases evaluated
        passed_cases: Number of cases where verdict matched
        failed_cases: Number of cases where verdict didn't match
        accuracy: Overall verdict accuracy
        precision: Precision for detecting malicious cases
        recall: Recall for detecting malicious cases
        f1_score: F1 score for malicious detection
        severity_accuracy: Accuracy of severity predictions
        confusion_matrix: Confusion matrix as nested dict
        verdict_metrics: Detailed verdict metrics per class
        technique_recall: Recall for MITRE technique detection
        avg_execution_time: Average execution time per case
        results: Individual case results
    """

    total_cases: int
    passed_cases: int
    failed_cases: int
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    severity_accuracy: float
    confusion_matrix: dict[str, dict[str, int]]
    verdict_metrics: VerdictMetrics | None = None
    technique_recall: float = 0.0
    avg_execution_time: float = 0.0
    results: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self):
        """Populate verdict_metrics if not provided."""
        if self.verdict_metrics is None:
            self.verdict_metrics = VerdictMetrics(
                accuracy=self.accuracy,
                precision=self.precision,
                recall=self.recall,
                f1_score=self.f1_score,
            )

    def to_dict(self) -> dict[str, Any]:
        """Convert report to dictionary for serialization."""
        return {
            "total_cases": self.total_cases,
            "passed_cases": self.passed_cases,
            "failed_cases": self.failed_cases,
            "accuracy": self.accuracy,
            "precision": self.precision,
            "recall": self.recall,
            "f1_score": self.f1_score,
            "severity_accuracy": self.severity_accuracy,
            "confusion_matrix": self.confusion_matrix,
            "technique_recall": self.technique_recall,
            "avg_execution_time": self.avg_execution_time,
            "results": self.results,
        }

    def summary(self) -> str:
        """Generate a human-readable summary of the evaluation."""
        lines = [
            "=" * 50,
            "EVALUATION REPORT",
            "=" * 50,
            f"Total Cases: {self.total_cases}",
            f"Passed: {self.passed_cases} | Failed: {self.failed_cases}",
            "",
            "--- Verdict Metrics ---",
            f"Accuracy:  {self.accuracy:.2%}",
            f"Precision: {self.precision:.2%}",
            f"Recall:    {self.recall:.2%}",
            f"F1 Score:  {self.f1_score:.2%}",
            "",
            f"Severity Accuracy: {self.severity_accuracy:.2%}",
            f"Technique Recall:  {self.technique_recall:.2%}",
            "",
            f"Avg Execution Time: {self.avg_execution_time:.2f}s",
            "=" * 50,
        ]
        return "\n".join(lines)


def calculate_verdict_metrics(
    predictions: list[str],
    labels: list[str],
) -> VerdictMetrics:
    """Calculate verdict classification metrics.

    Uses binary classification approach where 'malicious' is the positive class
    and 'benign'/'suspicious' are negative. Also computes per-class metrics.

    Args:
        predictions: List of predicted verdicts
        labels: List of ground truth verdicts

    Returns:
        VerdictMetrics with accuracy, precision, recall, F1
    """
    if not predictions or not labels:
        return VerdictMetrics(
            accuracy=0.0,
            precision=0.0,
            recall=0.0,
            f1_score=0.0,
        )

    if len(predictions) != len(labels):
        raise ValueError(f"Length mismatch: {len(predictions)} predictions vs {len(labels)} labels")

    total = len(labels)
    correct = sum(1 for pred, lbl in zip(predictions, labels) if pred == lbl)
    accuracy = correct / total if total > 0 else 0.0

    # Binary metrics treating 'malicious' as positive class
    # For security, we want to catch all malicious cases (high recall)
    # while minimizing false positives (high precision)
    true_positives = sum(
        1 for pred, lbl in zip(predictions, labels) if pred == "malicious" and lbl == "malicious"
    )
    false_positives = sum(
        1 for pred, lbl in zip(predictions, labels) if pred == "malicious" and lbl != "malicious"
    )
    false_negatives = sum(
        1 for pred, lbl in zip(predictions, labels) if pred != "malicious" and lbl == "malicious"
    )

    precision = (
        true_positives / (true_positives + false_positives)
        if (true_positives + false_positives) > 0
        else 0.0
    )
    recall = (
        true_positives / (true_positives + false_negatives)
        if (true_positives + false_negatives) > 0
        else 0.0
    )
    f1_score = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

    # Per-class metrics
    classes = sorted(set(predictions) | set(labels))
    per_class_metrics = {}

    for cls in classes:
        cls_tp = sum(1 for pred, lbl in zip(predictions, labels) if pred == cls and lbl == cls)
        cls_fp = sum(1 for pred, lbl in zip(predictions, labels) if pred == cls and lbl != cls)
        cls_fn = sum(1 for pred, lbl in zip(predictions, labels) if pred != cls and lbl == cls)

        cls_precision = cls_tp / (cls_tp + cls_fp) if (cls_tp + cls_fp) > 0 else 0.0
        cls_recall = cls_tp / (cls_tp + cls_fn) if (cls_tp + cls_fn) > 0 else 0.0
        cls_f1 = (
            2 * cls_precision * cls_recall / (cls_precision + cls_recall)
            if (cls_precision + cls_recall) > 0
            else 0.0
        )

        per_class_metrics[cls] = {
            "precision": cls_precision,
            "recall": cls_recall,
            "f1_score": cls_f1,
            "support": sum(1 for lbl in labels if lbl == cls),
        }

    return VerdictMetrics(
        accuracy=accuracy,
        precision=precision,
        recall=recall,
        f1_score=f1_score,
        per_class_metrics=per_class_metrics,
    )


def calculate_severity_accuracy(
    predictions: list[str | None],
    labels: list[str | None],
) -> float:
    """Calculate severity prediction accuracy.

    Only counts cases where both prediction and label are not None.

    Args:
        predictions: List of predicted severities
        labels: List of ground truth severities

    Returns:
        Accuracy as float between 0 and 1
    """
    if not predictions or not labels:
        return 0.0

    if len(predictions) != len(labels):
        raise ValueError(f"Length mismatch: {len(predictions)} predictions vs {len(labels)} labels")

    # Only count cases where both have values
    valid_pairs = [
        (pred, lbl)
        for pred, lbl in zip(predictions, labels)
        if pred is not None and lbl is not None
    ]

    if not valid_pairs:
        return 0.0

    correct = sum(1 for pred, lbl in valid_pairs if pred == lbl)
    return correct / len(valid_pairs)


def generate_confusion_matrix(
    predictions: list[str],
    labels: list[str],
) -> dict[str, dict[str, int]]:
    """Generate a confusion matrix as a nested dictionary.

    Args:
        predictions: List of predicted values
        labels: List of ground truth values

    Returns:
        Nested dict where result[actual][predicted] = count
    """
    if not predictions or not labels:
        return {}

    if len(predictions) != len(labels):
        raise ValueError(f"Length mismatch: {len(predictions)} predictions vs {len(labels)} labels")

    # Get all classes
    classes = sorted(set(predictions) | set(labels))

    # Initialize matrix
    matrix: dict[str, dict[str, int]] = {
        actual: {predicted: 0 for predicted in classes} for actual in classes
    }

    # Populate matrix
    for pred, label in zip(predictions, labels):
        matrix[label][pred] += 1

    return matrix


def calculate_technique_recall(
    predicted_techniques: list[list[str]],
    expected_techniques: list[list[str]],
) -> float:
    """Calculate recall for MITRE ATT&CK technique detection.

    Measures what fraction of expected techniques were correctly identified.

    Args:
        predicted_techniques: List of technique ID lists (one per case)
        expected_techniques: List of expected technique ID lists (one per case)

    Returns:
        Recall as float between 0 and 1
    """
    if not predicted_techniques or not expected_techniques:
        return 0.0

    if len(predicted_techniques) != len(expected_techniques):
        raise ValueError(
            f"Length mismatch: {len(predicted_techniques)} predictions "
            f"vs {len(expected_techniques)} labels"
        )

    total_expected = 0
    total_found = 0

    for predicted, expected in zip(predicted_techniques, expected_techniques):
        if not expected:
            continue

        total_expected += len(expected)
        predicted_set = set(predicted)

        for technique in expected:
            if technique in predicted_set:
                total_found += 1

    return total_found / total_expected if total_expected > 0 else 0.0


def format_confusion_matrix(matrix: dict[str, dict[str, int]]) -> str:
    """Format confusion matrix as a readable string.

    Args:
        matrix: Confusion matrix from generate_confusion_matrix

    Returns:
        Formatted string representation
    """
    if not matrix:
        return "Empty confusion matrix"

    classes = list(matrix.keys())
    max_label_len = max(len(c) for c in classes)
    cell_width = max(5, max_label_len)

    # Header
    header = " " * (max_label_len + 2) + "Predicted".center(len(classes) * (cell_width + 1))
    labels = " " * (max_label_len + 2) + "".join(c.center(cell_width + 1) for c in classes)

    lines = [
        "Confusion Matrix",
        "-" * len(header),
        header,
        labels,
        "-" * len(header),
    ]

    # Rows
    for actual in classes:
        row_values = [str(matrix[actual].get(pred, 0)).center(cell_width) for pred in classes]
        row = f"{actual.ljust(max_label_len)} |" + " ".join(row_values)
        lines.append(row)

    return "\n".join(lines)
