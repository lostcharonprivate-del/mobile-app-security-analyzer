"""Findings about the package container itself.

Most analyzers describe what the app does. This one describes what the *archive*
does — a member that would escape the extraction directory, or a structure that
disagrees with the file's extension, is a property of a package built to attack
whoever unpacks it, and is worth reporting before any code is discussed.
"""

from __future__ import annotations

from typing import Iterable

from masa.analyzers.base import Analyzer, register
from masa.context import ScanContext
from masa.models import Confidence, Finding, Platform, Severity


@register
class ArchiveAnalyzer(Analyzer):
    name = "archive"
    description = "Malformed or hostile package container structure"
    platforms = (Platform.ANDROID, Platform.IOS)

    def analyze(self, ctx: ScanContext) -> Iterable[Finding]:
        package = ctx.package

        if package.unsafe_members:
            by_reason: dict[str, list[str]] = {}
            for member in package.unsafe_members:
                by_reason.setdefault(member.reason, []).append(member.name)

            evidence = [
                self.evidence(
                    ctx,
                    location=name,
                    text=f"{reason}: {name}",
                    redact=False,
                )
                for reason, names in sorted(by_reason.items())
                for name in names[:5]
            ]
            traversal = any(
                "traversal" in reason or "absolute" in reason for reason in by_reason
            )
            yield self.finding(
                ctx,
                rule_id="ARC-UNSAFE-MEMBERS",
                title="Archive contains members that would escape the extraction directory",
                severity=Severity.CRITICAL if traversal else Severity.HIGH,
                owasp="M8",
                cwe="CWE-22",
                masvs="MASVS-PLATFORM",
                description=(
                    f"{len(package.unsafe_members)} archive member(s) are unsafe to "
                    "extract: "
                    + "; ".join(
                        f"{reason} ({len(names)})" for reason, names in sorted(by_reason.items())
                    )
                    + ". A legitimate build tool does not produce these. An entry "
                    "with a `..` path or an absolute path overwrites files outside "
                    "the target directory in any tool that extracts naively, and a "
                    "symlink member redirects a later write anywhere on disk. This "
                    "analyzer refused all of them, so nothing was written outside "
                    "its sandbox."
                ),
                remediation=(
                    "Do not unpack this file with a tool that has not been hardened "
                    "against path traversal. Treat the package as hostile and confirm "
                    "its provenance before analysing it further."
                ),
                evidence=evidence,
                references=["https://cwe.mitre.org/data/definitions/22.html"],
                metadata={"reasons": {k: len(v) for k, v in by_reason.items()}},
            )

        for anomaly in package.anomalies:
            yield self.finding(
                ctx,
                rule_id="ARC-ANOMALY",
                title="Package structure does not match its declared type",
                severity=Severity.INFO,
                owasp="M8",
                masvs="MASVS-PLATFORM",
                confidence=Confidence.HIGH,
                description=(
                    f"{anomaly}. This is reported because the tool identifies "
                    "packages by content rather than by file extension, and the two "
                    "disagreed."
                ),
                remediation=(
                    "Confirm the file is what it claims to be. A mismatch is often "
                    "harmless (a renamed file) but is also how a package gets past "
                    "a filter that trusts extensions."
                ),
                evidence=[
                    self.evidence(ctx, package.file_name, anomaly, redact=False)
                ],
            )
