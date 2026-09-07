"""Analyzer plugin framework.

One class per check category. Registering an analyzer is the only thing needed to
add it to the pipeline — the runner discovers everything in the registry, and the
report/scoring layers work off `Finding` alone, so no other file changes.
"""

from __future__ import annotations

import abc
import time
from dataclasses import dataclass, field
from typing import Callable, Iterable, Iterator, Sequence

from masa.context import ScanContext
from masa.models import Confidence, Evidence, Finding, Platform, Severity
from masa.redact import snippet


class Analyzer(abc.ABC):
    """Base class for a category of checks."""

    name: str = ""
    description: str = ""
    platforms: tuple[Platform, ...] = (Platform.ANDROID, Platform.IOS)

    @abc.abstractmethod
    def analyze(self, ctx: ScanContext) -> Iterable[Finding]:
        """Yield findings for this package. Must not raise on malformed input."""

    def applies_to(self, platform: Platform) -> bool:
        return platform in self.platforms

    # -- helpers shared by concrete analyzers ---------------------------------

    def finding(
        self,
        ctx: ScanContext,
        *,
        rule_id: str,
        title: str,
        severity: Severity,
        owasp: str,
        description: str,
        remediation: str,
        evidence: Sequence[Evidence] = (),
        cwe: str | None = None,
        masvs: str | None = None,
        confidence: Confidence = Confidence.HIGH,
        references: Sequence[str] = (),
        metadata: dict | None = None,
    ) -> Finding:
        capped = list(evidence)[: ctx.limits.max_evidence_per_finding]
        # Metadata ends up in the JSON report, which is shared like any other
        # output, so it goes through the same redaction as evidence snippets.
        extra = _redact_metadata(dict(metadata or {}), ctx.limits.snippet_chars)
        if len(evidence) > len(capped):
            extra["evidence_truncated"] = len(evidence) - len(capped)
        return Finding(
            rule_id=rule_id,
            title=title,
            severity=severity,
            owasp=owasp,
            description=description,
            remediation=remediation,
            evidence=capped,
            cwe=cwe,
            masvs=masvs,
            confidence=confidence,
            analyzer=self.name,
            references=list(references),
            metadata=extra,
        )

    @staticmethod
    def evidence(
        ctx: ScanContext,
        location: str,
        text: str = "",
        line: int | None = None,
        secret: str | None = None,
        redact: bool = True,
    ) -> Evidence:
        return Evidence(
            location=location,
            line=line,
            snippet=snippet(
                text, limit=ctx.limits.snippet_chars, secret=secret, redact=redact
            ),
        )


def _redact_metadata(value, limit: int):
    """Recursively redact strings in a metadata structure.

    Analyzers routinely put strings recovered from the package into metadata —
    matched resource names, library identifiers, host lists. Any of those can be
    a credential, so none of them reaches the report unredacted.
    """
    if isinstance(value, str):
        return snippet(value, limit=limit)
    if isinstance(value, dict):
        return {key: _redact_metadata(item, limit) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact_metadata(item, limit) for item in value]
    return value


_REGISTRY: list[type[Analyzer]] = []


def register(cls: type[Analyzer]) -> type[Analyzer]:
    """Class decorator that adds an analyzer to the pipeline."""
    if not cls.name:
        raise ValueError(f"{cls.__name__} must define a name")
    if any(existing.name == cls.name for existing in _REGISTRY):
        raise ValueError(f"duplicate analyzer name: {cls.name}")
    _REGISTRY.append(cls)
    return cls


def all_analyzers() -> list[Analyzer]:
    """Instantiate every registered analyzer, in registration order."""
    return [cls() for cls in _REGISTRY]


def registry_names() -> list[str]:
    return [cls.name for cls in _REGISTRY]
