"""Self-contained HTML report.

Every string in a finding — file names, code snippets, class names — originates
in an untrusted package, so the template is rendered with Jinja2 autoescaping on
and nothing is ever marked safe. A report that executed script from the APK it
just analysed would be a delivery mechanism rather than a report.

The output has no external references at all: no CDN, no web fonts, no images.
It is one file that opens anywhere, including on a machine with no network.
"""

from __future__ import annotations

import re
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from masa.models import OWASP_MOBILE_TOP_10, Report, Severity
from masa.scoring import explain, score_findings

# Escaping alone does not make a URL safe: `javascript:alert(1)` contains no
# HTML-special character, so it survives escaping intact and then executes when
# the reader clicks the link. Only http(s) references become anchors.
_SAFE_URL = re.compile(r"^https?://[^\s<>\"\']+$", re.IGNORECASE)


def is_safe_url(value: str) -> bool:
    return bool(_SAFE_URL.match(value or ""))

_TEMPLATE_DIR = Path(__file__).parent / "templates"

_SEVERITY_ORDER = [s.label for s in sorted(Severity, key=lambda s: -s.rank)]


def _environment() -> Environment:
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        # autoescape is on for every extension this renders, not just .html.
        autoescape=select_autoescape(
            enabled_extensions=("html", "j2", "htm", "xml"),
            default_for_string=True,
            default=True,
        ),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["is_safe_url"] = is_safe_url
    return env


def render_html(report: Report) -> str:
    env = _environment()
    template = env.get_template("report.html.j2")
    grouped = report.by_owasp()
    breakdown = score_findings(report.findings)

    return template.render(
        report=report,
        app=report.app,
        stats=report.stats,
        grouped=grouped,
        owasp=OWASP_MOBILE_TOP_10,
        severity_order=_SEVERITY_ORDER,
        severity_counts=report.severity_counts(),
        breakdown=breakdown,
        scoring_explanation=explain(),
        generated=report.generated_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
    )


def write_html(report: Report, path: Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_html(report), encoding="utf-8")
    return path
