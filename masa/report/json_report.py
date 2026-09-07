"""Machine-readable output for CI and downstream tooling."""

from __future__ import annotations

import json
from pathlib import Path

from masa.models import Report


def render_json(report: Report, indent: int | None = 2) -> str:
    """Serialize the report. The schema is versioned by `schema_version`."""
    return json.dumps(report.as_dict(), indent=indent, ensure_ascii=False, default=str)


def write_json(report: Report, path: Path, indent: int | None = 2) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_json(report, indent), encoding="utf-8")
    return path
