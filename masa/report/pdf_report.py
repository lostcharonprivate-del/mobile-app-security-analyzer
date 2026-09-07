"""Optional PDF export.

WeasyPrint renders the same self-contained HTML the tool already produces, so
there is no second template to keep in sync and no headless browser to install.
It is an optional extra because WeasyPrint needs system libraries (pango, cairo)
that are not worth making a hard requirement of a CLI whose primary outputs are
HTML and JSON.

Install with: pip install "mobile-app-security-analyzer[pdf]"
"""

from __future__ import annotations

from pathlib import Path

from masa.errors import MasaError
from masa.models import Report
from masa.report.html_report import render_html


class PdfUnavailable(MasaError):
    """WeasyPrint is not installed, or its system libraries are missing."""


def pdf_available() -> bool:
    try:
        import weasyprint  # noqa: F401
    except Exception:
        # WeasyPrint raises OSError, not ImportError, when its native libraries
        # are absent, so anything at all here means PDF export is unavailable.
        return False
    return True


def write_pdf(report: Report, path: Path) -> Path:
    """Render the report to PDF. Raises PdfUnavailable when WeasyPrint is absent."""
    try:
        from weasyprint import HTML
    except Exception as exc:
        raise PdfUnavailable(
            "PDF export needs WeasyPrint and its system libraries (pango, cairo). "
            'Install with: pip install "mobile-app-security-analyzer[pdf]". '
            "HTML and JSON output are always available."
        ) from exc

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    # base_url is irrelevant — the HTML has no external references by design —
    # but passing it keeps WeasyPrint from probing the filesystem.
    HTML(string=render_html(report), base_url=str(path.parent)).write_pdf(str(path))
    return path
