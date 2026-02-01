"""Test case dataset loading and management for agent evaluation.

This module provides:
- TestCase dataclass for representing evaluation test cases
- load_test_cases function for loading from YAML files
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import yaml  # type: ignore[import-untyped]


@dataclass
class TestCase:
    """A single test case for agent evaluation.

    Attributes:
        id: Unique identifier for the test case
        name: Human-readable name/description
        alert_data: The raw alert data to be processed by the agent
        expected_verdict: Expected classification (malicious, benign, suspicious)
        expected_severity: Expected severity level
        expected_techniques: List of expected MITRE ATT&CK technique IDs
        category: Optional category for grouping (e.g., "phishing", "malware")
        tags: Optional tags for filtering test cases
    """

    id: str
    name: str
    alert_data: dict[str, Any]
    expected_verdict: Literal["malicious", "benign", "suspicious"]
    expected_severity: Literal["critical", "high", "medium", "low", "informational"] | None = None
    expected_techniques: list[str] = field(default_factory=list)
    category: str | None = None
    tags: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        """Validate test case after initialization."""
        if not self.id:
            raise ValueError("TestCase id cannot be empty")
        if not self.name:
            raise ValueError("TestCase name cannot be empty")
        if not self.alert_data:
            raise ValueError("TestCase alert_data cannot be empty")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TestCase:
        """Create a TestCase from a dictionary (e.g., parsed from YAML).

        Args:
            data: Dictionary with test case data

        Returns:
            TestCase instance

        Raises:
            ValueError: If required fields are missing
        """
        # Handle nested 'expected' structure from YAML
        expected = data.get("expected", {})

        # Extract alert data - support both 'alert' and 'alert_data' keys
        alert_data = data.get("alert") or data.get("alert_data")
        if alert_data is None:
            raise ValueError(f"Test case '{data.get('id', 'unknown')}' missing alert/alert_data")

        return cls(
            id=data["id"],
            name=data["name"],
            alert_data=alert_data,
            expected_verdict=expected.get("verdict", data.get("expected_verdict")),
            expected_severity=expected.get("severity", data.get("expected_severity")),
            expected_techniques=expected.get("techniques", data.get("expected_techniques", [])),
            category=data.get("category"),
            tags=data.get("tags", []),
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert TestCase to dictionary for serialization."""
        return {
            "id": self.id,
            "name": self.name,
            "alert_data": self.alert_data,
            "expected_verdict": self.expected_verdict,
            "expected_severity": self.expected_severity,
            "expected_techniques": self.expected_techniques,
            "category": self.category,
            "tags": self.tags,
        }


def load_test_cases(path: str) -> list[TestCase]:
    """Load test cases from YAML files.

    Args:
        path: Path to a YAML file or directory containing YAML files

    Returns:
        List of TestCase instances

    Raises:
        FileNotFoundError: If the path doesn't exist
        ValueError: If YAML parsing fails or required fields are missing
    """
    path_obj = Path(path)

    if not path_obj.exists():
        raise FileNotFoundError(f"Test case path not found: {path}")

    test_cases: list[TestCase] = []

    if path_obj.is_file():
        # Load single file
        test_cases.extend(_load_yaml_file(path_obj))
    elif path_obj.is_dir():
        # Load all YAML files in directory
        yaml_files = sorted(path_obj.glob("*.yaml")) + sorted(path_obj.glob("*.yml"))
        for yaml_file in yaml_files:
            test_cases.extend(_load_yaml_file(yaml_file))
    else:
        raise ValueError(f"Path is neither a file nor directory: {path}")

    return test_cases


def _load_yaml_file(file_path: Path) -> list[TestCase]:
    """Load test cases from a single YAML file.

    Args:
        file_path: Path to the YAML file

    Returns:
        List of TestCase instances from the file
    """
    with open(file_path, encoding="utf-8") as f:
        content = yaml.safe_load(f)

    if content is None:
        return []

    # Infer category from filename if not specified
    category = file_path.stem

    # Support both list of test cases and single test case
    if isinstance(content, list):
        cases = content
    elif isinstance(content, dict):
        cases = [content]
    else:
        raise ValueError(f"Invalid YAML structure in {file_path}: expected list or dict")

    test_cases = []
    for case_data in cases:
        # Set category from filename if not explicitly provided
        if case_data.get("category") is None:
            case_data["category"] = category
        test_cases.append(TestCase.from_dict(case_data))

    return test_cases


def save_test_cases(test_cases: list[TestCase], path: str) -> None:
    """Save test cases to a YAML file.

    Args:
        test_cases: List of TestCase instances to save
        path: Output file path
    """
    # Convert to YAML-friendly format with nested 'expected' structure
    yaml_data: list[dict[str, Any]] = []
    for tc in test_cases:
        expected: dict[str, Any] = {
            "verdict": tc.expected_verdict,
        }
        if tc.expected_severity:
            expected["severity"] = tc.expected_severity
        if tc.expected_techniques:
            expected["techniques"] = tc.expected_techniques
        case_dict: dict[str, Any] = {
            "id": tc.id,
            "name": tc.name,
            "alert": tc.alert_data,
            "expected": expected,
        }
        if tc.category:
            case_dict["category"] = tc.category
        if tc.tags:
            case_dict["tags"] = tc.tags
        yaml_data.append(case_dict)

    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(yaml_data, f, default_flow_style=False, sort_keys=False)
