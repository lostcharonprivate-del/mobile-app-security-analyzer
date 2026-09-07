"""Core data model: severities, findings, app metadata and the report envelope."""

from __future__ import annotations

import dataclasses
import enum
import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


class Severity(enum.Enum):
    """Finding severity, ordered so comparisons and sorting work naturally."""

    CRITICAL = ("Critical", 5, 10.0)
    HIGH = ("High", 4, 7.0)
    MEDIUM = ("Medium", 3, 4.0)
    LOW = ("Low", 2, 1.5)
    INFO = ("Info", 1, 0.0)

    def __init__(self, label: str, rank: int, weight: float) -> None:
        self.label = label
        self.rank = rank
        self.weight = weight

    def __lt__(self, other: "Severity") -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank

    @classmethod
    def parse(cls, value: str) -> "Severity":
        want = value.strip().upper()
        for member in cls:
            if member.name == want or member.label.upper() == want:
                return member
        raise ValueError(f"unknown severity: {value!r}")


class Confidence(enum.Enum):
    """How sure the rule is. Low-confidence findings are reported but de-weighted."""

    HIGH = ("High", 1.0)
    MEDIUM = ("Medium", 0.7)
    LOW = ("Low", 0.4)

    def __init__(self, label: str, weight: float) -> None:
        self.label = label
        self.weight = weight


class Platform(enum.Enum):
    ANDROID = "android"
    IOS = "ios"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class OwaspCategory:
    """One OWASP Mobile Top 10 (2024) entry."""

    id: str
    title: str
    description: str


# OWASP Mobile Top 10 — 2024 release.
OWASP_MOBILE_TOP_10: dict[str, OwaspCategory] = {
    c.id: c
    for c in [
        OwaspCategory(
            "M1",
            "Improper Credential Usage",
            "Hardcoded credentials, or credentials transmitted/stored insecurely, let an "
            "attacker who reads the package authenticate as the app or its users.",
        ),
        OwaspCategory(
            "M2",
            "Inadequate Supply Chain Security",
            "Third-party components bundled into the app carry their own vulnerabilities, "
            "which the app inherits without the developer writing a line of vulnerable code.",
        ),
        OwaspCategory(
            "M3",
            "Insecure Authentication/Authorization",
            "Weak identification of the user or of the caller of an app component, letting "
            "an attacker reach functionality they should not.",
        ),
        OwaspCategory(
            "M4",
            "Insufficient Input/Output Validation",
            "Data from intents, URL schemes, WebViews or remote responses is trusted without "
            "validation, opening injection and code-execution surfaces.",
        ),
        OwaspCategory(
            "M5",
            "Insecure Communication",
            "Traffic that is unencrypted, or encrypted with validation disabled, can be read "
            "or modified by anyone on the network path.",
        ),
        OwaspCategory(
            "M6",
            "Inadequate Privacy Controls",
            "Personal data is collected, logged or shared more broadly than the app's function "
            "requires, or than the user was told.",
        ),
        OwaspCategory(
            "M7",
            "Insufficient Binary Protections",
            "The shipped binary offers no resistance to inspection or tampering, making "
            "reverse engineering and repackaging cheap.",
        ),
        OwaspCategory(
            "M8",
            "Security Misconfiguration",
            "Insecure defaults or debug settings left enabled in the shipped build.",
        ),
        OwaspCategory(
            "M9",
            "Insecure Data Storage",
            "Sensitive data written to device storage without encryption or access control, "
            "readable by other apps, by backups, or by anyone with the unlocked device.",
        ),
        OwaspCategory(
            "M10",
            "Insufficient Cryptography",
            "Broken or misused cryptographic primitives that fail to provide the "
            "confidentiality or integrity the app relies on.",
        ),
    ]
}

# MASVS control groups, used to give each finding a second, control-oriented axis.
MASVS_GROUPS: dict[str, str] = {
    "MASVS-STORAGE": "Secure storage of sensitive data on a device",
    "MASVS-CRYPTO": "Cryptographic functionality used to protect sensitive data",
    "MASVS-AUTH": "Authentication and authorisation mechanisms",
    "MASVS-NETWORK": "Secure network communication",
    "MASVS-PLATFORM": "Secure interaction with the underlying mobile platform",
    "MASVS-CODE": "Security best practices for data processing and keeping dependencies current",
    "MASVS-RESILIENCE": "Resilience to reverse engineering and tampering",
    "MASVS-PRIVACY": "Privacy controls protecting user data",
}


@dataclass
class Evidence:
    """A single piece of supporting evidence, already redacted for display."""

    location: str
    """Human-readable location, e.g. 'AndroidManifest.xml' or 'classes.dex:string_pool'."""

    line: int | None = None
    snippet: str = ""
    """Redacted, length-capped excerpt. Never contains a full secret value."""

    def as_dict(self) -> dict[str, Any]:
        return {"location": self.location, "line": self.line, "snippet": self.snippet}


@dataclass
class Finding:
    """One security finding produced by an analyzer rule."""

    rule_id: str
    title: str
    severity: Severity
    owasp: str
    """OWASP Mobile Top 10 (2024) id, e.g. 'M5'."""

    description: str
    remediation: str
    evidence: list[Evidence] = field(default_factory=list)
    cwe: str | None = None
    masvs: str | None = None
    confidence: Confidence = Confidence.HIGH
    analyzer: str = ""
    references: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.owasp not in OWASP_MOBILE_TOP_10:
            raise ValueError(
                f"finding {self.rule_id!r} maps to unknown OWASP id {self.owasp!r}"
            )
        if self.masvs is not None and self.masvs not in MASVS_GROUPS:
            raise ValueError(
                f"finding {self.rule_id!r} maps to unknown MASVS group {self.masvs!r}"
            )

    @property
    def owasp_category(self) -> OwaspCategory:
        return OWASP_MOBILE_TOP_10[self.owasp]

    @property
    def fingerprint(self) -> str:
        """Stable id for dedup and for diffing two scans of the same app."""
        locations = sorted({e.location for e in self.evidence})
        raw = "\x1f".join([self.rule_id, self.title, *locations])
        return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:16]

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "fingerprint": self.fingerprint,
            "title": self.title,
            "severity": self.severity.label,
            "confidence": self.confidence.label,
            "owasp": {
                "id": self.owasp,
                "title": self.owasp_category.title,
            },
            "cwe": self.cwe,
            "masvs": self.masvs,
            "analyzer": self.analyzer,
            "description": self.description,
            "remediation": self.remediation,
            "references": list(self.references),
            "evidence": [e.as_dict() for e in self.evidence],
            "metadata": dict(self.metadata),
        }


@dataclass
class AppInfo:
    """Package metadata shown in the report's 'app info' section."""

    platform: Platform = Platform.UNKNOWN
    file_name: str = ""
    file_size: int = 0
    sha256: str = ""
    package_name: str | None = None
    version_name: str | None = None
    version_code: str | None = None
    min_sdk: str | None = None
    target_sdk: str | None = None
    min_os_version: str | None = None
    permissions: list[str] = field(default_factory=list)
    components: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    signing: dict[str, Any] = field(default_factory=dict)
    libraries: list[dict[str, Any]] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        data = dataclasses.asdict(self)
        data["platform"] = self.platform.value
        return data


@dataclass
class ScanStats:
    """What the pipeline actually managed to look at — surfaces silent degradation."""

    files_scanned: int = 0
    bytes_scanned: int = 0
    strings_extracted: int = 0
    duration_seconds: float = 0.0
    decompilers_used: list[str] = field(default_factory=list)
    degraded: list[str] = field(default_factory=list)
    """Human-readable notes about analysis that could not run (missing tools, timeouts)."""

    def as_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass
class Report:
    """Full scan result: app metadata, findings, score and coverage stats."""

    app: AppInfo
    findings: list[Finding] = field(default_factory=list)
    stats: ScanStats = field(default_factory=ScanStats)
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    tool_version: str = ""
    risk_score: float = 0.0
    risk_grade: str = "A"
    errors: list[str] = field(default_factory=list)

    def by_owasp(self) -> dict[str, list[Finding]]:
        """Findings grouped by OWASP id, in M1..M10 order, severity-sorted within a group."""
        grouped: dict[str, list[Finding]] = {}
        for finding in self.findings:
            grouped.setdefault(finding.owasp, []).append(finding)
        for items in grouped.values():
            items.sort(key=lambda f: (-f.severity.rank, f.rule_id))
        return {
            key: grouped[key]
            for key in sorted(grouped, key=lambda k: int(k[1:]))
        }

    def severity_counts(self) -> dict[str, int]:
        counts = {s.label: 0 for s in Severity}
        for finding in self.findings:
            counts[finding.severity.label] += 1
        return counts

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "tool": {"name": "mobile-app-security-analyzer", "version": self.tool_version},
            "generated_at": self.generated_at.isoformat(),
            "app": self.app.as_dict(),
            "risk": {
                "score": round(self.risk_score, 1),
                "grade": self.risk_grade,
                "severity_counts": self.severity_counts(),
            },
            "findings": [f.as_dict() for f in self.findings],
            "owasp_coverage": {
                oid: {
                    "title": cat.title,
                    "finding_count": len(self.by_owasp().get(oid, [])),
                }
                for oid, cat in OWASP_MOBILE_TOP_10.items()
            },
            "stats": self.stats.as_dict(),
            "errors": list(self.errors),
        }
