"""Playbook ingester for YAML playbook files.

Ingests security playbooks from YAML files in the config/playbooks directory.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

import structlog
import yaml

from tw_ai.rag.ingestion.base import BaseIngester
from tw_ai.rag.models import PlaybookDocument

if TYPE_CHECKING:
    from tw_ai.rag.vector_store import VectorStore

logger = structlog.get_logger()


class PlaybookIngester(BaseIngester):
    """Ingester for security playbooks from YAML files."""

    def __init__(self, vector_store: VectorStore) -> None:
        """Initialize playbook ingester."""
        super().__init__(vector_store)

    @property
    def collection_name(self) -> str:
        """Get the playbooks collection name."""
        return self._vector_store._config.playbooks_collection

    async def ingest(self, playbooks_dir: Path) -> int:
        """Ingest playbooks from a directory.

        Args:
            playbooks_dir: Path to directory containing YAML playbooks.

        Returns:
            Number of playbooks ingested.
        """
        if not playbooks_dir.exists():
            logger.warning("playbooks_dir_not_found", path=str(playbooks_dir))
            return 0

        yaml_files = list(playbooks_dir.glob("*.yaml")) + list(
            playbooks_dir.glob("*.yml")
        )

        logger.info(
            "ingesting_playbooks",
            directory=str(playbooks_dir),
            file_count=len(yaml_files),
        )

        documents = []
        for yaml_file in yaml_files:
            try:
                doc = self._parse_playbook(yaml_file)
                if doc:
                    documents.append(doc)
            except Exception as e:
                logger.error(
                    "playbook_parse_error",
                    file=str(yaml_file),
                    error=str(e),
                )

        if documents:
            self._add_documents(documents)

        logger.info("playbook_ingestion_complete", count=len(documents))
        return len(documents)

    def _parse_playbook(self, yaml_file: Path) -> PlaybookDocument | None:
        """Parse a single YAML playbook file.

        Args:
            yaml_file: Path to YAML file.

        Returns:
            PlaybookDocument or None if parsing fails.
        """
        with open(yaml_file) as f:
            data = yaml.safe_load(f)

        if not data or not isinstance(data, dict):
            return None

        name = data.get("name", yaml_file.stem)
        version = str(data.get("version", "1.0"))
        description = data.get("description", "")

        # Extract trigger types from trigger section
        trigger = data.get("trigger", {})
        trigger_types = trigger.get("alert_types", [])
        if isinstance(trigger_types, str):
            trigger_types = [trigger_types]

        # Count stages
        stages = data.get("stages", [])
        stage_count = len(stages) if isinstance(stages, list) else 0

        # Check for branches
        has_branches = "branches" in data and bool(data["branches"])

        # Build content for embedding
        content = self._build_content(data, name, description)

        return PlaybookDocument(
            id=f"playbook_{name}",
            content=content,
            name=name,
            version=version,
            trigger_types=trigger_types,
            stage_count=stage_count,
            has_branches=has_branches,
        )

    def _build_content(
        self,
        data: dict[str, Any],
        name: str,
        description: str,
    ) -> str:
        """Build rich text content for playbook embedding.

        Args:
            data: Parsed YAML data.
            name: Playbook name.
            description: Playbook description.

        Returns:
            Text content for embedding.
        """
        parts = [f"Security Playbook: {name}"]

        if description:
            parts.append(f"Description: {description}")

        # Add trigger info
        trigger = data.get("trigger", {})
        if sources := trigger.get("sources"):
            parts.append(f"Trigger sources: {', '.join(sources)}")
        if alert_types := trigger.get("alert_types"):
            parts.append(f"Alert types: {', '.join(alert_types)}")

        # Add stage names
        stages = data.get("stages", [])
        if stages:
            stage_names = [s.get("name", "unnamed") for s in stages if isinstance(s, dict)]
            parts.append(f"Stages: {', '.join(stage_names)}")

        # Add branch names
        branches = data.get("branches", {})
        if branches:
            parts.append(f"Branches: {', '.join(branches.keys())}")

        # Add SLA info
        sla = data.get("sla", {})
        if sla:
            sla_items = [f"{k}: {v}" for k, v in sla.items()]
            parts.append(f"SLA: {', '.join(sla_items)}")

        return "\n".join(parts)
