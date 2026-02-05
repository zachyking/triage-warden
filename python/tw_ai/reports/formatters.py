"""Report export formatters for different output formats.

This module provides formatters to export InvestigationReport objects
to JSON, HTML, and PDF formats.

Stage 2.1.3 Implementation.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from tw_ai.reports.models import InvestigationReport

# Template directory path
TEMPLATES_DIR = Path(__file__).parent / "templates"


class ReportFormatter(ABC):
    """Base class for report formatters."""

    @abstractmethod
    def format(self, report: InvestigationReport) -> str | bytes:
        """Format the report for export.

        Args:
            report: The investigation report to format.

        Returns:
            Formatted report as string (JSON, HTML) or bytes (PDF).
        """
        pass

    @abstractmethod
    def content_type(self) -> str:
        """Return the MIME content type for this format."""
        pass

    @abstractmethod
    def file_extension(self) -> str:
        """Return the file extension for this format."""
        pass


class JsonFormatter(ReportFormatter):
    """Formatter for JSON export."""

    def __init__(self, indent: int = 2, include_raw_data: bool = True):
        """Initialize JSON formatter.

        Args:
            indent: Indentation level for pretty printing.
            include_raw_data: Whether to include raw alert data and enrichments.
        """
        self.indent = indent
        self.include_raw_data = include_raw_data

    def format(self, report: InvestigationReport) -> str:
        """Format report as JSON string."""
        data = report.model_dump(mode="json")

        # Optionally exclude large raw data sections
        if not self.include_raw_data:
            data.pop("raw_alert_data", None)
            data.pop("enrichments", None)

        return json.dumps(data, indent=self.indent, default=str)

    def content_type(self) -> str:
        return "application/json"

    def file_extension(self) -> str:
        return ".json"


class HtmlFormatter(ReportFormatter):
    """Formatter for HTML export using Jinja2 templates."""

    def __init__(self, template_name: str = "full_report.html"):
        """Initialize HTML formatter.

        Args:
            template_name: Name of the Jinja2 template to use.
        """
        self.template_name = template_name
        self._env: Any = None

    @property
    def env(self) -> Any:
        """Lazy-load Jinja2 environment."""
        if self._env is None:
            try:
                from jinja2 import Environment, FileSystemLoader, select_autoescape
            except ImportError as e:
                raise ImportError(
                    "Jinja2 is required for HTML export. " "Install it with: pip install jinja2"
                ) from e

            self._env = Environment(
                loader=FileSystemLoader(str(TEMPLATES_DIR)),
                autoescape=select_autoescape(["html", "xml"]),
            )
        return self._env

    def format(self, report: InvestigationReport) -> str:
        """Format report as HTML string."""
        template = self.env.get_template(self.template_name)
        result: str = template.render(report=report)
        return result

    def content_type(self) -> str:
        return "text/html"

    def file_extension(self) -> str:
        return ".html"


class PdfFormatter(ReportFormatter):
    """Formatter for PDF export.

    Uses weasyprint to convert HTML to PDF. Falls back to a simpler
    approach if weasyprint is not available.
    """

    def __init__(self, include_raw_data: bool = False):
        """Initialize PDF formatter.

        Args:
            include_raw_data: Whether to include raw data in appendix.
        """
        self.include_raw_data = include_raw_data
        self._html_formatter = HtmlFormatter()

    def format(self, report: InvestigationReport) -> bytes:
        """Format report as PDF bytes."""
        # First render to HTML
        html_content = self._html_formatter.format(report)

        # Try weasyprint first
        try:
            return self._render_with_weasyprint(html_content)
        except ImportError:
            pass

        # Fall back to reportlab if weasyprint not available
        try:
            return self._render_with_reportlab(report)
        except ImportError:
            pass

        raise ImportError(
            "PDF export requires either weasyprint or reportlab. "
            "Install with: pip install weasyprint OR pip install reportlab"
        )

    def _render_with_weasyprint(self, html_content: str) -> bytes:
        """Render PDF using weasyprint."""
        from weasyprint import HTML

        html = HTML(string=html_content, base_url=str(TEMPLATES_DIR))
        result: bytes = html.write_pdf()
        return result

    def _render_with_reportlab(self, report: InvestigationReport) -> bytes:
        """Render PDF using reportlab (fallback).

        This produces a simpler PDF compared to weasyprint but works
        without system dependencies.
        """
        from io import BytesIO

        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import inch
        from reportlab.platypus import (
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )

        buffer = BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=0.75 * inch,
            leftMargin=0.75 * inch,
            topMargin=0.75 * inch,
            bottomMargin=0.75 * inch,
        )

        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            "Title",
            parent=styles["Heading1"],
            fontSize=18,
            spaceAfter=12,
        )
        heading_style = ParagraphStyle(
            "Heading",
            parent=styles["Heading2"],
            fontSize=14,
            spaceBefore=12,
            spaceAfter=6,
        )
        body_style = styles["BodyText"]

        story = []

        # Title
        story.append(Paragraph("Investigation Report", title_style))
        story.append(Paragraph(f"Incident ID: {report.metadata.incident_id}", body_style))
        story.append(
            Paragraph(
                f"Generated: {report.metadata.generated_at.strftime('%Y-%m-%d %H:%M UTC')}",
                body_style,
            )
        )
        story.append(Spacer(1, 12))

        # Executive Summary
        story.append(Paragraph("Executive Summary", heading_style))
        story.append(Paragraph(report.executive_summary, body_style))
        story.append(Spacer(1, 6))

        # Verdict
        story.append(
            Paragraph(
                f"<b>Verdict:</b> {report.verdict.verdict_display} "
                f"({report.verdict.confidence}% confidence)",
                body_style,
            )
        )
        story.append(Paragraph(f"<b>Severity:</b> {report.verdict.severity_display}", body_style))
        story.append(Spacer(1, 12))

        # Evidence Summary
        if report.evidence:
            story.append(Paragraph("Evidence Summary", heading_style))
            evidence_data = [
                ["Total Items", "Avg Confidence", "High Conf.", "Sources"],
                [
                    str(report.evidence_summary.total_evidence),
                    f"{report.evidence_summary.average_confidence}%",
                    str(report.evidence_summary.high_confidence_count),
                    str(len(report.evidence_summary.sources_used)),
                ],
            ]
            evidence_table = Table(evidence_data, colWidths=[1.5 * inch] * 4)
            evidence_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a365d")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, 0), 10),
                        ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
                        ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#f7fafc")),
                        ("GRID", (0, 0), (-1, -1), 1, colors.HexColor("#e2e8f0")),
                    ]
                )
            )
            story.append(evidence_table)
            story.append(Spacer(1, 12))

        # Evidence Table
        if report.evidence:
            story.append(Paragraph("Evidence Details", heading_style))
            evidence_rows = [["#", "Source", "Finding", "Confidence"]]
            for item in report.evidence[:10]:  # Limit to first 10 for space
                evidence_rows.append(
                    [
                        str(item.order),
                        item.source_name,
                        item.finding[:60] + "..." if len(item.finding) > 60 else item.finding,
                        f"{item.confidence}%",
                    ]
                )
            if len(report.evidence) > 10:
                evidence_rows.append(["...", f"+{len(report.evidence) - 10} more items", "", ""])

            col_widths = [0.4 * inch, 1.3 * inch, 3.5 * inch, 0.8 * inch]
            ev_table = Table(evidence_rows, colWidths=col_widths)
            ev_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a365d")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, -1), 9),
                        ("ALIGN", (0, 0), (0, -1), "CENTER"),
                        ("ALIGN", (-1, 0), (-1, -1), "CENTER"),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                        (
                            "ROWBACKGROUNDS",
                            (0, 1),
                            (-1, -1),
                            [colors.white, colors.HexColor("#f7fafc")],
                        ),
                    ]
                )
            )
            story.append(ev_table)
            story.append(Spacer(1, 12))

        # MITRE Techniques
        if report.mitre_techniques:
            story.append(Paragraph("MITRE ATT&CK Techniques", heading_style))
            for technique in report.mitre_techniques:
                story.append(
                    Paragraph(
                        f"<b>{technique.technique_id}</b> - {technique.name} "
                        f"({technique.tactic})",
                        body_style,
                    )
                )
                story.append(Paragraph(f"<i>{technique.relevance}</i>", body_style))
            story.append(Spacer(1, 12))

        # IOCs
        if report.indicators:
            story.append(Paragraph("Indicators of Compromise", heading_style))
            ioc_rows = [["Type", "Value", "Verdict"]]
            for ioc in report.indicators[:15]:
                ioc_rows.append(
                    [
                        ioc.indicator_type.upper(),
                        ioc.value[:50] + "..." if len(ioc.value) > 50 else ioc.value,
                        ioc.verdict.title(),
                    ]
                )
            ioc_table = Table(ioc_rows, colWidths=[1 * inch, 4 * inch, 1 * inch])
            ioc_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a365d")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, -1), 9),
                        ("FONTNAME", (1, 1), (1, -1), "Courier"),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                    ]
                )
            )
            story.append(ioc_table)
            story.append(Spacer(1, 12))

        # Recommended Actions
        if report.recommended_actions:
            story.append(Paragraph("Recommended Actions", heading_style))
            for action in report.recommended_actions:
                # Priority color mapping (for potential future styling)
                _ = {
                    "immediate": "#742a2a",
                    "high": "#c53030",
                    "medium": "#dd6b20",
                    "low": "#38a169",
                }.get(action.priority, "#4a5568")
                story.append(
                    Paragraph(
                        f"<b>[{action.priority.upper()}]</b> {action.action}",
                        body_style,
                    )
                )
                story.append(Paragraph(f"<i>Reason: {action.reason}</i>", body_style))
                story.append(Spacer(1, 6))

        # Build PDF
        doc.build(story)
        return buffer.getvalue()

    def content_type(self) -> str:
        return "application/pdf"

    def file_extension(self) -> str:
        return ".pdf"


def get_formatter(format_name: str) -> ReportFormatter:
    """Get a formatter instance by format name.

    Args:
        format_name: Format name ('json', 'html', or 'pdf').

    Returns:
        Appropriate ReportFormatter instance.

    Raises:
        ValueError: If format is not supported.
    """
    formatters = {
        "json": JsonFormatter,
        "html": HtmlFormatter,
        "pdf": PdfFormatter,
    }

    format_lower = format_name.lower()
    if format_lower not in formatters:
        raise ValueError(
            f"Unsupported format: {format_name}. "
            f"Supported formats: {', '.join(formatters.keys())}"
        )

    formatter: ReportFormatter = formatters[format_lower]()
    return formatter


def export_report(
    report: InvestigationReport,
    format_name: str,
    output_path: str | Path | None = None,
) -> str | bytes:
    """Export a report to the specified format.

    Args:
        report: The investigation report to export.
        format_name: Format name ('json', 'html', or 'pdf').
        output_path: Optional file path to write the output.

    Returns:
        Formatted report content (str for JSON/HTML, bytes for PDF).
    """
    formatter = get_formatter(format_name)
    content = formatter.format(report)

    if output_path:
        path = Path(output_path)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8")

    return content
