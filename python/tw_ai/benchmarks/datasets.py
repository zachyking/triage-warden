"""Benchmark dataset definitions for security task evaluation.

This module defines the structure of benchmark datasets and examples
used for evaluating AI models on security-specific tasks.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]


class TaskType(str, Enum):
    """Types of security tasks in the benchmark suite."""

    INCIDENT_SUMMARIZATION = "incident_summarization"
    SEVERITY_RATING = "severity_rating"
    VERDICT_CLASSIFICATION = "verdict_classification"
    MITRE_MAPPING = "mitre_mapping"
    IOC_QUERY_GENERATION = "ioc_query_generation"
    ACTION_RECOMMENDATION = "action_recommendation"


@dataclass
class BenchmarkExample:
    """A single example for benchmark evaluation.

    Each example contains:
    - Input data (the incident/alert to analyze)
    - Expected output (ground truth for evaluation)
    - Metadata for categorization and analysis
    """

    id: str
    task_type: TaskType
    input_data: dict[str, Any]
    expected_output: dict[str, Any]
    difficulty: str = "medium"  # easy, medium, hard
    category: str | None = None  # phishing, malware, etc.
    tags: list[str] = field(default_factory=list)
    source: str | None = None  # Where this example came from

    def __post_init__(self) -> None:
        """Validate example after initialization."""
        if not self.id:
            raise ValueError("BenchmarkExample id cannot be empty")
        if not self.input_data:
            raise ValueError("BenchmarkExample input_data cannot be empty")
        if not self.expected_output:
            raise ValueError("BenchmarkExample expected_output cannot be empty")
        if isinstance(self.task_type, str):
            self.task_type = TaskType(self.task_type)
        if self.difficulty not in ("easy", "medium", "hard"):
            raise ValueError(f"Invalid difficulty: {self.difficulty}")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BenchmarkExample:
        """Create a BenchmarkExample from a dictionary."""
        return cls(
            id=data["id"],
            task_type=TaskType(data["task_type"]),
            input_data=data["input"],
            expected_output=data["expected"],
            difficulty=data.get("difficulty", "medium"),
            category=data.get("category"),
            tags=data.get("tags", []),
            source=data.get("source"),
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "id": self.id,
            "task_type": self.task_type.value,
            "input": self.input_data,
            "expected": self.expected_output,
            "difficulty": self.difficulty,
            "category": self.category,
            "tags": self.tags,
            "source": self.source,
        }


@dataclass
class BenchmarkDataset:
    """A collection of benchmark examples for a specific task.

    Attributes:
        name: Human-readable name for the dataset
        task_type: The type of security task this dataset tests
        description: Description of what this dataset evaluates
        examples: List of benchmark examples
        version: Dataset version for tracking changes
    """

    name: str
    task_type: TaskType
    description: str
    examples: list[BenchmarkExample]
    version: str = "1.0"
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate dataset after initialization."""
        if not self.name:
            raise ValueError("BenchmarkDataset name cannot be empty")
        if not self.examples:
            raise ValueError("BenchmarkDataset must have at least one example")

    def __len__(self) -> int:
        return len(self.examples)

    def __iter__(self) -> Any:
        return iter(self.examples)

    def filter_by_difficulty(self, difficulty: str) -> list[BenchmarkExample]:
        """Filter examples by difficulty level."""
        return [e for e in self.examples if e.difficulty == difficulty]

    def filter_by_category(self, category: str) -> list[BenchmarkExample]:
        """Filter examples by category."""
        return [e for e in self.examples if e.category == category]

    def filter_by_tags(self, tags: list[str]) -> list[BenchmarkExample]:
        """Filter examples that have any of the specified tags."""
        tag_set = set(tags)
        return [e for e in self.examples if tag_set & set(e.tags)]

    def get_statistics(self) -> dict[str, Any]:
        """Get statistics about this dataset."""
        categories: dict[str, int] = {}
        difficulties: dict[str, int] = {"easy": 0, "medium": 0, "hard": 0}

        for example in self.examples:
            if example.category:
                categories[example.category] = categories.get(example.category, 0) + 1
            difficulties[example.difficulty] += 1

        return {
            "name": self.name,
            "task_type": self.task_type.value,
            "total_examples": len(self.examples),
            "by_difficulty": difficulties,
            "by_category": categories,
        }

    @classmethod
    def from_yaml(cls, path: str | Path) -> BenchmarkDataset:
        """Load a dataset from a YAML file."""
        path = Path(path)
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)

        examples = [BenchmarkExample.from_dict(e) for e in data.get("examples", [])]

        return cls(
            name=data["name"],
            task_type=TaskType(data["task_type"]),
            description=data.get("description", ""),
            examples=examples,
            version=data.get("version", "1.0"),
            metadata=data.get("metadata", {}),
        )

    def to_yaml(self, path: str | Path) -> None:
        """Save the dataset to a YAML file."""
        data = {
            "name": self.name,
            "task_type": self.task_type.value,
            "description": self.description,
            "version": self.version,
            "metadata": self.metadata,
            "examples": [e.to_dict() for e in self.examples],
        }

        with open(path, "w", encoding="utf-8") as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)


class SecurityBenchmark:
    """Complete security benchmark suite containing all task datasets.

    This class aggregates multiple task-specific datasets into a single
    benchmark that can be run against different AI models.

    Example:
        benchmark = SecurityBenchmark()
        benchmark.load_datasets("/path/to/datasets")

        # Or use built-in datasets
        benchmark = SecurityBenchmark.with_builtin_datasets()

        # Run specific tasks
        for task in benchmark.tasks:
            dataset = benchmark.get_dataset(task)
            # evaluate model on dataset
    """

    def __init__(self) -> None:
        self.datasets: dict[TaskType, BenchmarkDataset] = {}
        self._tasks: list[TaskType] = []

    @property
    def tasks(self) -> list[TaskType]:
        """Get list of available task types."""
        return list(self.datasets.keys())

    def add_dataset(self, dataset: BenchmarkDataset) -> None:
        """Add a dataset to the benchmark."""
        self.datasets[dataset.task_type] = dataset

    def get_dataset(self, task_type: TaskType) -> BenchmarkDataset | None:
        """Get dataset for a specific task type."""
        return self.datasets.get(task_type)

    def load_datasets(self, directory: str | Path) -> None:
        """Load all datasets from a directory.

        Expects YAML files named by task type (e.g., verdict_classification.yaml)
        """
        directory = Path(directory)
        if not directory.exists():
            raise FileNotFoundError(f"Dataset directory not found: {directory}")

        for yaml_file in directory.glob("*.yaml"):
            dataset = BenchmarkDataset.from_yaml(yaml_file)
            self.add_dataset(dataset)

    def get_total_examples(self) -> int:
        """Get total number of examples across all datasets."""
        return sum(len(ds) for ds in self.datasets.values())

    def get_summary(self) -> dict[str, Any]:
        """Get summary statistics for the entire benchmark."""
        tasks: dict[str, Any] = {}
        summary: dict[str, Any] = {
            "total_tasks": len(self.datasets),
            "total_examples": self.get_total_examples(),
            "tasks": tasks,
        }

        for task_type, dataset in self.datasets.items():
            tasks[task_type.value] = dataset.get_statistics()

        return summary

    @classmethod
    def with_builtin_datasets(cls) -> SecurityBenchmark:
        """Create a benchmark with built-in sample datasets.

        These are minimal datasets for testing. For comprehensive evaluation,
        load full datasets from files.
        """
        benchmark = cls()

        # Add sample datasets for each task type
        benchmark.add_dataset(cls._create_verdict_classification_dataset())
        benchmark.add_dataset(cls._create_severity_rating_dataset())
        benchmark.add_dataset(cls._create_mitre_mapping_dataset())
        benchmark.add_dataset(cls._create_summarization_dataset())
        benchmark.add_dataset(cls._create_action_recommendation_dataset())
        benchmark.add_dataset(cls._create_ioc_query_dataset())

        return benchmark

    @staticmethod
    def _create_verdict_classification_dataset() -> BenchmarkDataset:
        """Create sample verdict classification dataset."""
        examples = [
            BenchmarkExample(
                id="vc_001",
                task_type=TaskType.VERDICT_CLASSIFICATION,
                input_data={
                    "alert_type": "email_security",
                    "subject": "Urgent: Your account has been compromised",
                    "sender": "security@paypa1-alerts.com",
                    "sender_domain_age_days": 3,
                    "contains_link": True,
                    "link_domain": "paypal-secure-login.xyz",
                    "recipient": "user@company.com",
                },
                expected_output={"verdict": "true_positive", "confidence": 95},
                difficulty="easy",
                category="phishing",
                tags=["credential-theft", "spoofing"],
            ),
            BenchmarkExample(
                id="vc_002",
                task_type=TaskType.VERDICT_CLASSIFICATION,
                input_data={
                    "alert_type": "email_security",
                    "subject": "Your order has shipped",
                    "sender": "notifications@amazon.com",
                    "sender_domain_age_days": 8500,
                    "contains_link": True,
                    "link_domain": "amazon.com",
                    "recipient": "user@company.com",
                },
                expected_output={"verdict": "false_positive", "confidence": 90},
                difficulty="easy",
                category="legitimate",
                tags=["shipping", "notification"],
            ),
            BenchmarkExample(
                id="vc_003",
                task_type=TaskType.VERDICT_CLASSIFICATION,
                input_data={
                    "alert_type": "endpoint_detection",
                    "process_name": "powershell.exe",
                    "command_line": "powershell -enc UwB0AGEAcgB0AC0AUwBsAGUAZQBwACAALQBzACAANQA=",
                    "parent_process": "outlook.exe",
                    "user": "domain\\user1",
                    "network_connections": ["185.234.72.14:443"],
                },
                expected_output={"verdict": "true_positive", "confidence": 85},
                difficulty="medium",
                category="malware",
                tags=["powershell", "encoded-command", "outlook-spawn"],
            ),
            BenchmarkExample(
                id="vc_004",
                task_type=TaskType.VERDICT_CLASSIFICATION,
                input_data={
                    "alert_type": "endpoint_detection",
                    "process_name": "svchost.exe",
                    "command_line": "C:\\Windows\\System32\\svchost.exe -k netsvcs",
                    "parent_process": "services.exe",
                    "user": "SYSTEM",
                    "network_connections": [],
                },
                expected_output={"verdict": "false_positive", "confidence": 95},
                difficulty="easy",
                category="legitimate",
                tags=["windows-service", "system-process"],
            ),
            BenchmarkExample(
                id="vc_005",
                task_type=TaskType.VERDICT_CLASSIFICATION,
                input_data={
                    "alert_type": "network_ids",
                    "source_ip": "10.0.1.50",
                    "dest_ip": "89.248.165.200",
                    "dest_port": 443,
                    "bytes_sent": 1024000,
                    "bytes_received": 50000,
                    "signature": "ET TROJAN Cobalt Strike Beacon Activity",
                    "timestamp": "2024-01-15T02:30:00Z",
                },
                expected_output={"verdict": "true_positive", "confidence": 90},
                difficulty="medium",
                category="c2",
                tags=["cobalt-strike", "beacon", "exfiltration"],
            ),
        ]

        return BenchmarkDataset(
            name="Verdict Classification",
            task_type=TaskType.VERDICT_CLASSIFICATION,
            description="Classify security alerts as true positive, false positive, or suspicious",
            examples=examples,
        )

    @staticmethod
    def _create_severity_rating_dataset() -> BenchmarkDataset:
        """Create sample severity rating dataset."""
        examples = [
            BenchmarkExample(
                id="sr_001",
                task_type=TaskType.SEVERITY_RATING,
                input_data={
                    "alert_type": "data_exfiltration",
                    "data_volume_mb": 500,
                    "data_classification": "confidential",
                    "destination": "external_cloud_storage",
                    "user": "admin@company.com",
                },
                expected_output={
                    "severity": "critical",
                    "justification": "Large volume confidential data exfiltration",
                },
                difficulty="easy",
                category="data-theft",
            ),
            BenchmarkExample(
                id="sr_002",
                task_type=TaskType.SEVERITY_RATING,
                input_data={
                    "alert_type": "failed_login",
                    "attempts": 3,
                    "source_ip": "corporate_vpn",
                    "user": "john.doe@company.com",
                    "time_window_minutes": 5,
                },
                expected_output={
                    "severity": "low",
                    "justification": "Minor failed login attempts from known source",
                },
                difficulty="easy",
                category="authentication",
            ),
            BenchmarkExample(
                id="sr_003",
                task_type=TaskType.SEVERITY_RATING,
                input_data={
                    "alert_type": "ransomware_detected",
                    "affected_systems": 15,
                    "encryption_started": True,
                    "lateral_movement": True,
                    "domain_admin_compromised": True,
                },
                expected_output={
                    "severity": "critical",
                    "justification": "Active ransomware with domain compromise",
                },
                difficulty="easy",
                category="ransomware",
            ),
            BenchmarkExample(
                id="sr_004",
                task_type=TaskType.SEVERITY_RATING,
                input_data={
                    "alert_type": "suspicious_process",
                    "process": "cmd.exe",
                    "parent": "explorer.exe",
                    "user_initiated": True,
                    "network_activity": False,
                },
                expected_output={
                    "severity": "informational",
                    "justification": "Normal user-initiated command prompt",
                },
                difficulty="medium",
                category="endpoint",
            ),
            BenchmarkExample(
                id="sr_005",
                task_type=TaskType.SEVERITY_RATING,
                input_data={
                    "alert_type": "privilege_escalation",
                    "technique": "token_manipulation",
                    "source_user": "standard_user",
                    "target_privileges": "local_admin",
                    "system": "workstation",
                },
                expected_output={
                    "severity": "high",
                    "justification": "Successful privilege escalation on workstation",
                },
                difficulty="medium",
                category="privilege-escalation",
            ),
        ]

        return BenchmarkDataset(
            name="Severity Rating",
            task_type=TaskType.SEVERITY_RATING,
            description="Rate the severity of security incidents (critical, high, medium, low, informational)",
            examples=examples,
        )

    @staticmethod
    def _create_mitre_mapping_dataset() -> BenchmarkDataset:
        """Create sample MITRE ATT&CK mapping dataset."""
        examples = [
            BenchmarkExample(
                id="mm_001",
                task_type=TaskType.MITRE_MAPPING,
                input_data={
                    "description": "Attacker sent spearphishing email with malicious Excel attachment containing macros",
                    "indicators": ["malicious_macro.xlsm", "powershell.exe spawned from excel.exe"],
                },
                expected_output={
                    "techniques": [
                        {
                            "id": "T1566.001",
                            "name": "Spearphishing Attachment",
                            "tactic": "Initial Access",
                        },
                        {"id": "T1204.002", "name": "Malicious File", "tactic": "Execution"},
                    ]
                },
                difficulty="easy",
                category="phishing",
            ),
            BenchmarkExample(
                id="mm_002",
                task_type=TaskType.MITRE_MAPPING,
                input_data={
                    "description": "Attacker created new local admin account and used RDP for lateral movement",
                    "indicators": [
                        "net user hacker /add",
                        "net localgroup administrators hacker /add",
                        "mstsc.exe",
                    ],
                },
                expected_output={
                    "techniques": [
                        {"id": "T1136.001", "name": "Local Account", "tactic": "Persistence"},
                        {
                            "id": "T1021.001",
                            "name": "Remote Desktop Protocol",
                            "tactic": "Lateral Movement",
                        },
                    ]
                },
                difficulty="medium",
                category="lateral-movement",
            ),
            BenchmarkExample(
                id="mm_003",
                task_type=TaskType.MITRE_MAPPING,
                input_data={
                    "description": "Credential dumping using Mimikatz followed by pass-the-hash attack",
                    "indicators": ["mimikatz.exe", "sekurlsa::logonpasswords", "pth module"],
                },
                expected_output={
                    "techniques": [
                        {"id": "T1003.001", "name": "LSASS Memory", "tactic": "Credential Access"},
                        {"id": "T1550.002", "name": "Pass the Hash", "tactic": "Lateral Movement"},
                    ]
                },
                difficulty="medium",
                category="credential-theft",
            ),
            BenchmarkExample(
                id="mm_004",
                task_type=TaskType.MITRE_MAPPING,
                input_data={
                    "description": "Data staged to cloud storage before exfiltration over HTTPS",
                    "indicators": ["rclone.exe", "aws s3 cp", "encrypted archive created"],
                },
                expected_output={
                    "techniques": [
                        {"id": "T1074.001", "name": "Local Data Staging", "tactic": "Collection"},
                        {
                            "id": "T1567.002",
                            "name": "Exfiltration to Cloud Storage",
                            "tactic": "Exfiltration",
                        },
                    ]
                },
                difficulty="medium",
                category="exfiltration",
            ),
            BenchmarkExample(
                id="mm_005",
                task_type=TaskType.MITRE_MAPPING,
                input_data={
                    "description": "Process injection into lsass.exe using reflective DLL loading",
                    "indicators": [
                        "VirtualAllocEx",
                        "WriteProcessMemory",
                        "CreateRemoteThread",
                        "lsass.exe target",
                    ],
                },
                expected_output={
                    "techniques": [
                        {
                            "id": "T1055.001",
                            "name": "Dynamic-link Library Injection",
                            "tactic": "Defense Evasion",
                        },
                        {
                            "id": "T1055.001",
                            "name": "Dynamic-link Library Injection",
                            "tactic": "Privilege Escalation",
                        },
                    ]
                },
                difficulty="hard",
                category="process-injection",
            ),
        ]

        return BenchmarkDataset(
            name="MITRE ATT&CK Mapping",
            task_type=TaskType.MITRE_MAPPING,
            description="Map observed attack behaviors to MITRE ATT&CK techniques",
            examples=examples,
        )

    @staticmethod
    def _create_summarization_dataset() -> BenchmarkDataset:
        """Create sample incident summarization dataset."""
        examples = [
            BenchmarkExample(
                id="is_001",
                task_type=TaskType.INCIDENT_SUMMARIZATION,
                input_data={
                    "title": "Suspected phishing campaign targeting finance department",
                    "alerts": [
                        {
                            "time": "09:00",
                            "type": "email",
                            "detail": "Suspicious email from cfo@company-secure.net",
                        },
                        {
                            "time": "09:05",
                            "type": "email",
                            "detail": "5 more emails from same domain",
                        },
                        {
                            "time": "09:15",
                            "type": "web",
                            "detail": "User clicked link, redirected to credential harvester",
                        },
                        {
                            "time": "09:20",
                            "type": "auth",
                            "detail": "Failed login attempts from Ukraine IP",
                        },
                    ],
                    "affected_users": 3,
                    "timeline_hours": 1,
                },
                expected_output={
                    "summary": "Phishing campaign targeted finance department with CEO impersonation. 3 users received emails, 1 clicked malicious link. Credential harvesting attempt detected, followed by failed login attempts from suspicious IP.",
                    "key_findings": [
                        "CEO impersonation phishing",
                        "Credential harvesting page",
                        "External login attempts",
                    ],
                },
                difficulty="medium",
                category="phishing",
            ),
            BenchmarkExample(
                id="is_002",
                task_type=TaskType.INCIDENT_SUMMARIZATION,
                input_data={
                    "title": "Ransomware incident on file server",
                    "alerts": [
                        {
                            "time": "02:00",
                            "type": "edr",
                            "detail": "Suspicious process encryption activity",
                        },
                        {
                            "time": "02:05",
                            "type": "edr",
                            "detail": "Mass file modifications detected",
                        },
                        {
                            "time": "02:10",
                            "type": "network",
                            "detail": "C2 beacon to known ransomware infrastructure",
                        },
                        {
                            "time": "02:15",
                            "type": "file",
                            "detail": "Ransom note README.txt created",
                        },
                    ],
                    "affected_systems": 1,
                    "files_encrypted": 15000,
                },
                expected_output={
                    "summary": "Ransomware executed on file server at 02:00, encrypting 15,000 files. Active C2 communication detected. Ransom note deployed.",
                    "key_findings": [
                        "Ransomware encryption activity",
                        "Active C2 communication",
                        "15,000 files affected",
                    ],
                },
                difficulty="easy",
                category="ransomware",
            ),
        ]

        return BenchmarkDataset(
            name="Incident Summarization",
            task_type=TaskType.INCIDENT_SUMMARIZATION,
            description="Generate concise summaries of security incidents from alert data",
            examples=examples,
        )

    @staticmethod
    def _create_action_recommendation_dataset() -> BenchmarkDataset:
        """Create sample action recommendation dataset."""
        examples = [
            BenchmarkExample(
                id="ar_001",
                task_type=TaskType.ACTION_RECOMMENDATION,
                input_data={
                    "incident_type": "active_ransomware",
                    "severity": "critical",
                    "affected_system": "file_server",
                    "encryption_active": True,
                    "network_connected": True,
                },
                expected_output={
                    "actions": [
                        {
                            "action": "Isolate affected system from network immediately",
                            "priority": "immediate",
                        },
                        {"action": "Disable compromised user accounts", "priority": "immediate"},
                        {"action": "Preserve memory dump for forensics", "priority": "high"},
                        {"action": "Identify and block C2 infrastructure", "priority": "high"},
                        {
                            "action": "Assess backup integrity and recovery options",
                            "priority": "high",
                        },
                    ]
                },
                difficulty="medium",
                category="ransomware",
            ),
            BenchmarkExample(
                id="ar_002",
                task_type=TaskType.ACTION_RECOMMENDATION,
                input_data={
                    "incident_type": "credential_compromise",
                    "severity": "high",
                    "affected_account": "domain_admin",
                    "authentication_source": "external_ip",
                    "mfa_bypassed": True,
                },
                expected_output={
                    "actions": [
                        {"action": "Reset compromised account password", "priority": "immediate"},
                        {"action": "Revoke all active sessions", "priority": "immediate"},
                        {"action": "Review and reset MFA enrollment", "priority": "high"},
                        {"action": "Audit recent account activity", "priority": "high"},
                        {"action": "Check for persistence mechanisms", "priority": "medium"},
                    ]
                },
                difficulty="medium",
                category="credential-theft",
            ),
        ]

        return BenchmarkDataset(
            name="Action Recommendation",
            task_type=TaskType.ACTION_RECOMMENDATION,
            description="Recommend appropriate response actions for security incidents",
            examples=examples,
        )

    @staticmethod
    def _create_ioc_query_dataset() -> BenchmarkDataset:
        """Create sample IoC query generation dataset."""
        examples = [
            BenchmarkExample(
                id="iq_001",
                task_type=TaskType.IOC_QUERY_GENERATION,
                input_data={
                    "ioc_type": "ip_address",
                    "ioc_value": "185.234.72.14",
                    "query_target": "splunk",
                    "time_range": "last_7_days",
                },
                expected_output={
                    "query": 'index=* (src_ip="185.234.72.14" OR dest_ip="185.234.72.14") earliest=-7d',
                    "description": "Search for network traffic involving the suspicious IP",
                },
                difficulty="easy",
                category="network",
            ),
            BenchmarkExample(
                id="iq_002",
                task_type=TaskType.IOC_QUERY_GENERATION,
                input_data={
                    "ioc_type": "file_hash",
                    "ioc_value": "d41d8cd98f00b204e9800998ecf8427e",
                    "query_target": "crowdstrike",
                    "time_range": "last_30_days",
                },
                expected_output={
                    "query": "event_simpleName IN (ProcessRollup2, PeFileWritten) AND (SHA256HashData=d41d8cd98f00b204e9800998ecf8427e OR MD5HashData=d41d8cd98f00b204e9800998ecf8427e)",
                    "description": "Search for file execution or creation with matching hash",
                },
                difficulty="medium",
                category="endpoint",
            ),
            BenchmarkExample(
                id="iq_003",
                task_type=TaskType.IOC_QUERY_GENERATION,
                input_data={
                    "ioc_type": "domain",
                    "ioc_value": "malware-c2.evil.com",
                    "query_target": "splunk",
                    "time_range": "last_24_hours",
                },
                expected_output={
                    "query": 'index=dns OR index=proxy (query="*malware-c2.evil.com*" OR url="*malware-c2.evil.com*") earliest=-24h',
                    "description": "Search DNS and proxy logs for domain communication",
                },
                difficulty="easy",
                category="network",
            ),
        ]

        return BenchmarkDataset(
            name="IoC Query Generation",
            task_type=TaskType.IOC_QUERY_GENERATION,
            description="Generate SIEM queries to search for indicators of compromise",
            examples=examples,
        )
