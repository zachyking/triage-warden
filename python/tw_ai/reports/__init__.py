"""Investigation Report Generation for Triage Warden.

This module provides functionality to generate structured investigation reports
from incident data and AI triage analysis. Reports include executive summaries,
evidence tables, MITRE ATT&CK mappings, and recommended actions.

Also provides post-incident report generation (Stage 4.4.1).
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
from tw_ai.reports.post_incident import (
    PostIncidentReport,
    PostIncidentReportGenerator,
)

__all__ = [
    # Generator
    "InvestigationReportGenerator",
    "PostIncidentReportGenerator",
    # Models
    "InvestigationReport",
    "PostIncidentReport",
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
