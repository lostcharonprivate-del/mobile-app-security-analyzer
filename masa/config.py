"""Central limits and knobs.

Every bound the tool enforces against untrusted input lives here so the safety
envelope can be reviewed in one place instead of being scattered through the code.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from pathlib import Path

MB = 1024 * 1024
GB = 1024 * MB


@dataclass(frozen=True)
class Limits:
    """Hard bounds applied to untrusted archives and their contents."""

    max_input_bytes: int = 512 * MB
    """Largest package we will even open."""

    max_total_uncompressed_bytes: int = 4 * GB
    """Cap on the sum of declared uncompressed sizes across all entries."""

    max_entry_uncompressed_bytes: int = 512 * MB
    """Cap on any single entry's declared uncompressed size."""

    max_entries: int = 100_000
    """Cap on the number of archive members."""

    max_compression_ratio: float = 200.0
    """Total uncompressed / total compressed. Above this we call it a zip bomb."""

    min_ratio_check_bytes: int = 4 * MB
    """Ratio is only meaningful once there is some bulk; ignore it for tiny archives."""

    max_extract_bytes: int = 2 * GB
    """Bytes actually written to disk during extraction, enforced while streaming."""

    max_scan_file_bytes: int = 16 * MB
    """Largest single file an analyzer will read into memory for pattern matching."""

    max_scanned_files: int = 25_000
    """Cap on files fed to the content analyzers."""

    max_line_bytes: int = 64 * 1024
    """Lines longer than this are truncated before regex matching (ReDoS ceiling)."""

    max_strings_per_binary: int = 200_000
    """Cap on strings pulled out of a native binary or DEX string pool."""

    max_evidence_per_finding: int = 25
    """Keeps a single noisy rule from producing a multi-megabyte report."""

    snippet_chars: int = 160
    """Maximum characters of context shown in report evidence."""

    subprocess_timeout_seconds: int = 300
    """Wall-clock cap on any external decompiler invocation."""

    total_timeout_seconds: int = 1800
    """Wall-clock cap on the whole scan."""

    regex_timeout_seconds: float = 5.0
    """Budget for pattern matching a single file, checked between patterns."""

    max_xml_bytes: int = 32 * MB
    """Largest XML/plist document we will parse."""

    max_archive_depth: int = 1
    """We do not recursively extract archives found inside the package."""


DEFAULT_LIMITS = Limits()


@dataclass
class ScanConfig:
    """Runtime options for one scan."""

    limits: Limits = field(default_factory=lambda: DEFAULT_LIMITS)
    keep_artifacts: bool = False
    """Leave the decompiled tree on disk for the user's own review."""

    workdir: Path | None = None
    """Parent directory for the sandbox; defaults to the system temp dir."""

    enable_external_tools: bool = True
    """Allow apktool/jadx/otool invocation when they are on PATH."""

    enable_network: bool = False
    """Opt-in: allows the OSV.dev dependency lookup. Off by default; nothing about
    the analyzed file ever leaves the machine except library names and versions."""

    offline_only: bool = True
    """Mirror of `enable_network`, kept explicit so the default reads as a promise."""

    entropy_threshold: float = 4.3
    """Shannon entropy (bits/char) above which a long string is treated as secret-like."""

    min_entropy_length: int = 20
    max_entropy_length: int = 512
    disabled_rules: frozenset[str] = frozenset()
    disabled_analyzers: frozenset[str] = frozenset()
    severity_floor: str = "INFO"

    def with_network(self, enabled: bool) -> "ScanConfig":
        return replace(self, enable_network=enabled, offline_only=not enabled)
