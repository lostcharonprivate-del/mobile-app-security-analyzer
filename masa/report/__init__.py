"""Report rendering: JSON for tooling, HTML for people, PDF on request."""

from masa.report.json_report import render_json, write_json
from masa.report.html_report import render_html, write_html
from masa.report.pdf_report import PdfUnavailable, pdf_available, write_pdf

__all__ = [
    "render_json",
    "write_json",
    "render_html",
    "write_html",
    "write_pdf",
    "pdf_available",
    "PdfUnavailable",
]
