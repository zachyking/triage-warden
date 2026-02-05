"""Investigation Report Generation for Triage Warden.

This module provides functionality to generate structured investigation reports
from incident data and AI triage analysis. Reports include executive summaries,
evidence tables, MITRE ATT&CK mappings, and recommended actions.

Stage 2.1.3 Implementation.
"""

from tw_ai.reports.formatters import (
    HtmlFormatter,
    JsonFormatter,
    PdfFormatter,
    ReportFormatter,
    export_report,
    get_formatter,
)
from tw_ai.reports.generator import InvestigationReportGenerator
from tw_ai.reports.models import (
    InvestigationReport,
    ReportFormat,
    ReportMetadata,
)

__all__ = [
    # Generator
    "InvestigationReportGenerator",
    # Models
    "InvestigationReport",
    "ReportFormat",
    "ReportMetadata",
    # Formatters
    "ReportFormatter",
    "JsonFormatter",
    "HtmlFormatter",
    "PdfFormatter",
    "get_formatter",
    "export_report",
]
