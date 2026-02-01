"""Ingestion pipeline for RAG knowledge base.

This module provides ingesters for various data sources:
- MITRE ATT&CK techniques from built-in mappings
- Playbooks from YAML files
- Historical incidents from triage results
- Threat intelligence indicators
"""

from __future__ import annotations

from tw_ai.rag.ingestion.base import BaseIngester
from tw_ai.rag.ingestion.incidents import IncidentIngester
from tw_ai.rag.ingestion.mitre import MITREIngester
from tw_ai.rag.ingestion.playbooks import PlaybookIngester
from tw_ai.rag.ingestion.threat_intel import ThreatIntelIngester

__all__ = [
    "BaseIngester",
    "IncidentIngester",
    "MITREIngester",
    "PlaybookIngester",
    "ThreatIntelIngester",
]
