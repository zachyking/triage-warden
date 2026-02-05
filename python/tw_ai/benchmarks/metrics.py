"""Benchmark evaluation metrics for security tasks.

This module provides metrics for evaluating model performance on security tasks:
- Exact match accuracy
- F1 score for classification
- BLEU/ROUGE scores for text generation
- Task-specific metrics
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any


@dataclass
class TaskMetrics:
    """Metrics for a single task type.

    Attributes:
        task_name: Name of the task
        total_examples: Number of examples evaluated
        primary_score: Primary metric score (task-specific)
        all_scores: Dictionary of all metric scores
        per_example_scores: Scores for each individual example
    """

    task_name: str
    total_examples: int = 0
    primary_score: float = 0.0
    all_scores: dict[str, float] = field(default_factory=dict)
    per_example_scores: list[dict[str, float]] = field(default_factory=list)

    def add_example(self, scores: dict[str, float]) -> None:
        """Add scores from a single example."""
        self.per_example_scores.append(scores)
        self.total_examples += 1

        # Update aggregate scores
        for key, value in scores.items():
            if key not in self.all_scores:
                self.all_scores[key] = 0.0
            self.all_scores[key] += value

    def finalize(self) -> None:
        """Finalize metrics by computing averages."""
        if self.total_examples > 0:
            for key in self.all_scores:
                self.all_scores[key] /= self.total_examples
            self.primary_score = self.all_scores.get("primary", 0.0)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "task_name": self.task_name,
            "total_examples": self.total_examples,
            "primary_score": self.primary_score,
            "all_scores": self.all_scores,
        }


@dataclass
class BenchmarkMetrics:
    """Aggregate metrics across all benchmark tasks.

    Attributes:
        model_name: Name of the model being evaluated
        task_metrics: Metrics for each task type
        overall_score: Weighted average across all tasks
        total_examples: Total examples across all tasks
        total_time_seconds: Total evaluation time
    """

    model_name: str
    task_metrics: dict[str, TaskMetrics] = field(default_factory=dict)
    overall_score: float = 0.0
    total_examples: int = 0
    total_time_seconds: float = 0.0

    def add_task_metrics(self, task_name: str, metrics: TaskMetrics) -> None:
        """Add metrics for a task."""
        self.task_metrics[task_name] = metrics
        self.total_examples += metrics.total_examples

    def calculate_overall_score(self, weights: dict[str, float] | None = None) -> float:
        """Calculate weighted overall score.

        Args:
            weights: Optional task weights (default: equal weighting)

        Returns:
            Weighted average primary score
        """
        if not self.task_metrics:
            return 0.0

        if weights is None:
            # Equal weighting
            weights = {name: 1.0 for name in self.task_metrics}

        total_weight = sum(weights.get(name, 0) for name in self.task_metrics)
        if total_weight == 0:
            return 0.0

        weighted_sum = sum(
            metrics.primary_score * weights.get(name, 0)
            for name, metrics in self.task_metrics.items()
        )

        self.overall_score = weighted_sum / total_weight
        return self.overall_score

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "model_name": self.model_name,
            "overall_score": self.overall_score,
            "total_examples": self.total_examples,
            "total_time_seconds": self.total_time_seconds,
            "tasks": {name: m.to_dict() for name, m in self.task_metrics.items()},
        }

    def summary(self) -> str:
        """Generate a human-readable summary."""
        lines = [
            "=" * 60,
            f"BENCHMARK RESULTS: {self.model_name}",
            "=" * 60,
            f"Overall Score: {self.overall_score:.2%}",
            f"Total Examples: {self.total_examples}",
            f"Total Time: {self.total_time_seconds:.1f}s",
            "",
            "Task Breakdown:",
            "-" * 40,
        ]

        for name, metrics in sorted(self.task_metrics.items()):
            lines.append(f"  {name}:")
            lines.append(f"    Score: {metrics.primary_score:.2%}")
            lines.append(f"    Examples: {metrics.total_examples}")
            for metric_name, value in sorted(metrics.all_scores.items()):
                if metric_name != "primary":
                    lines.append(f"    {metric_name}: {value:.2%}")

        lines.append("=" * 60)
        return "\n".join(lines)


def calculate_exact_match(predicted: str, expected: str, case_sensitive: bool = False) -> float:
    """Calculate exact match score.

    Args:
        predicted: Predicted string
        expected: Expected string
        case_sensitive: Whether comparison is case-sensitive

    Returns:
        1.0 if exact match, 0.0 otherwise
    """
    if not case_sensitive:
        predicted = predicted.lower().strip()
        expected = expected.lower().strip()

    return 1.0 if predicted == expected else 0.0


def calculate_f1_score(
    predicted: set[str],
    expected: set[str],
) -> dict[str, float]:
    """Calculate precision, recall, and F1 score.

    Args:
        predicted: Set of predicted items
        expected: Set of expected items

    Returns:
        Dictionary with precision, recall, and f1_score
    """
    if not predicted and not expected:
        return {"precision": 1.0, "recall": 1.0, "f1_score": 1.0}

    if not predicted:
        return {"precision": 0.0, "recall": 0.0, "f1_score": 0.0}

    if not expected:
        return {"precision": 0.0, "recall": 1.0, "f1_score": 0.0}

    true_positives = len(predicted & expected)
    precision = true_positives / len(predicted)
    recall = true_positives / len(expected)

    if precision + recall == 0:
        f1 = 0.0
    else:
        f1 = 2 * precision * recall / (precision + recall)

    return {
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
    }


def calculate_bleu_score(
    predicted: str,
    expected: str,
    max_n: int = 4,
) -> float:
    """Calculate BLEU score for text similarity.

    Simplified BLEU implementation without smoothing.

    Args:
        predicted: Predicted text
        expected: Expected (reference) text
        max_n: Maximum n-gram size (default: 4)

    Returns:
        BLEU score between 0 and 1
    """
    # Tokenize
    pred_tokens = _tokenize(predicted)
    exp_tokens = _tokenize(expected)

    if not pred_tokens or not exp_tokens:
        return 0.0

    # Brevity penalty
    bp = min(1.0, len(pred_tokens) / len(exp_tokens)) if exp_tokens else 0.0

    # N-gram precision scores
    precisions = []
    for n in range(1, max_n + 1):
        pred_ngrams = _get_ngrams(pred_tokens, n)
        exp_ngrams = _get_ngrams(exp_tokens, n)

        if not pred_ngrams:
            precisions.append(0.0)
            continue

        # Count matches
        pred_counts = Counter(pred_ngrams)
        exp_counts = Counter(exp_ngrams)

        matches = sum(min(pred_counts[ng], exp_counts[ng]) for ng in pred_counts)
        total = sum(pred_counts.values())

        precisions.append(matches / total if total > 0 else 0.0)

    # Geometric mean of precisions
    if not any(precisions) or 0.0 in precisions:
        return 0.0

    import math

    log_sum = sum(math.log(p) for p in precisions if p > 0)
    geometric_mean = math.exp(log_sum / len(precisions))

    return bp * geometric_mean


def calculate_rouge_scores(
    predicted: str,
    expected: str,
) -> dict[str, float]:
    """Calculate ROUGE scores for text similarity.

    Computes ROUGE-1, ROUGE-2, and ROUGE-L scores.

    Args:
        predicted: Predicted text
        expected: Expected (reference) text

    Returns:
        Dictionary with rouge_1, rouge_2, and rouge_l scores
    """
    pred_tokens = _tokenize(predicted)
    exp_tokens = _tokenize(expected)

    if not pred_tokens or not exp_tokens:
        return {"rouge_1": 0.0, "rouge_2": 0.0, "rouge_l": 0.0}

    # ROUGE-1 (unigram overlap)
    rouge_1 = _rouge_n(pred_tokens, exp_tokens, 1)

    # ROUGE-2 (bigram overlap)
    rouge_2 = _rouge_n(pred_tokens, exp_tokens, 2)

    # ROUGE-L (longest common subsequence)
    rouge_l = _rouge_l(pred_tokens, exp_tokens)

    return {
        "rouge_1": rouge_1,
        "rouge_2": rouge_2,
        "rouge_l": rouge_l,
    }


def calculate_classification_metrics(
    predictions: list[str],
    labels: list[str],
    classes: list[str] | None = None,
) -> dict[str, Any]:
    """Calculate comprehensive classification metrics.

    Args:
        predictions: List of predicted class labels
        labels: List of ground truth labels
        classes: Optional list of class names

    Returns:
        Dictionary with accuracy, per-class metrics, and confusion matrix
    """
    if not predictions or not labels:
        return {
            "accuracy": 0.0,
            "macro_f1": 0.0,
            "per_class": {},
            "confusion_matrix": {},
        }

    if len(predictions) != len(labels):
        raise ValueError(f"Length mismatch: {len(predictions)} predictions vs {len(labels)} labels")

    if classes is None:
        classes = sorted(set(predictions) | set(labels))

    # Accuracy
    correct = sum(1 for pred, lbl in zip(predictions, labels) if pred == lbl)
    accuracy = correct / len(labels)

    # Per-class metrics
    per_class: dict[str, dict[str, float]] = {}
    for cls in classes:
        tp = sum(1 for p, lbl in zip(predictions, labels) if p == cls and lbl == cls)
        fp = sum(1 for p, lbl in zip(predictions, labels) if p == cls and lbl != cls)
        fn = sum(1 for p, lbl in zip(predictions, labels) if p != cls and lbl == cls)

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

        per_class[cls] = {
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "support": sum(1 for lbl in labels if lbl == cls),
        }

    # Macro F1
    macro_f1 = sum(m["f1"] for m in per_class.values()) / len(per_class) if per_class else 0.0

    # Confusion matrix
    confusion_matrix: dict[str, dict[str, int]] = {
        actual: {predicted: 0 for predicted in classes} for actual in classes
    }
    for pred, label in zip(predictions, labels):
        if label in confusion_matrix and pred in confusion_matrix[label]:
            confusion_matrix[label][pred] += 1

    return {
        "accuracy": accuracy,
        "macro_f1": macro_f1,
        "per_class": per_class,
        "confusion_matrix": confusion_matrix,
    }


def calculate_ordinal_distance(
    predicted: str,
    expected: str,
    order: list[str],
) -> float:
    """Calculate distance-based score for ordinal labels.

    Useful for severity ratings where partial credit is given.

    Args:
        predicted: Predicted ordinal label
        expected: Expected ordinal label
        order: List of labels in order (lowest to highest)

    Returns:
        Score between 0 and 1 (1 = exact match)
    """
    if predicted not in order or expected not in order:
        return 0.0

    pred_idx = order.index(predicted)
    exp_idx = order.index(expected)
    max_distance = len(order) - 1

    if max_distance == 0:
        return 1.0

    distance = abs(pred_idx - exp_idx)
    return 1.0 - (distance / max_distance)


# Helper functions


def _tokenize(text: str) -> list[str]:
    """Tokenize text into words."""
    # Simple word tokenization
    return re.findall(r"\b\w+\b", text.lower())


def _get_ngrams(tokens: list[str], n: int) -> list[tuple[str, ...]]:
    """Get n-grams from a list of tokens."""
    return [tuple(tokens[i : i + n]) for i in range(len(tokens) - n + 1)]


def _rouge_n(pred_tokens: list[str], exp_tokens: list[str], n: int) -> float:
    """Calculate ROUGE-N F1 score."""
    pred_ngrams = _get_ngrams(pred_tokens, n)
    exp_ngrams = _get_ngrams(exp_tokens, n)

    if not pred_ngrams or not exp_ngrams:
        return 0.0

    pred_counts = Counter(pred_ngrams)
    exp_counts = Counter(exp_ngrams)

    matches = sum(min(pred_counts[ng], exp_counts[ng]) for ng in pred_counts)

    precision = matches / len(pred_ngrams)
    recall = matches / len(exp_ngrams)

    if precision + recall == 0:
        return 0.0

    return 2 * precision * recall / (precision + recall)


def _rouge_l(pred_tokens: list[str], exp_tokens: list[str]) -> float:
    """Calculate ROUGE-L F1 score using LCS."""
    lcs_length = _lcs_length(pred_tokens, exp_tokens)

    if not pred_tokens or not exp_tokens:
        return 0.0

    precision = lcs_length / len(pred_tokens)
    recall = lcs_length / len(exp_tokens)

    if precision + recall == 0:
        return 0.0

    return 2 * precision * recall / (precision + recall)


def _lcs_length(seq1: list[str], seq2: list[str]) -> int:
    """Calculate length of longest common subsequence."""
    m, n = len(seq1), len(seq2)
    dp = [[0] * (n + 1) for _ in range(m + 1)]

    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if seq1[i - 1] == seq2[j - 1]:
                dp[i][j] = dp[i - 1][j - 1] + 1
            else:
                dp[i][j] = max(dp[i - 1][j], dp[i][j - 1])

    return dp[m][n]
