"""The ScanContext: everything the analyzers are allowed to look at.

Analyzers never touch the original package or run subprocesses themselves. They
receive a fully-populated, read-only view produced by the decompile layer, which
keeps the untrusted-input handling in one auditable place.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

from masa.config import ScanConfig
from masa.decompile.arsc import ResourceTable
from masa.decompile.axml import AxmlDocument
from masa.decompile.dex import DexFile
from masa.decompile.apksig import SigningInfo
from masa.ingest.safe_archive import iter_files
from masa.ingest.validator import PackageInfo
from masa.models import AppInfo, Platform

# Files worth reading as text. Anything else is treated as a binary blob and
# only has printable strings pulled out of it.
_TEXT_SUFFIXES = frozenset(
    {
        ".xml", ".json", ".txt", ".properties", ".plist", ".yml", ".yaml",
        ".java", ".kt", ".js", ".ts", ".html", ".htm", ".css", ".md", ".ini",
        ".cfg", ".conf", ".pem", ".key", ".crt", ".env", ".gradle", ".pro",
        ".mf", ".sf", ".strings", ".sql", ".graphql", ".csv", ".m", ".swift",
    }
)

_BINARY_SUFFIXES = frozenset({".so", ".dylib", ".a", ".dex", ".bin", ".dat"})

_PRINTABLE_RUN = re.compile(rb"[\x20-\x7e]{5,256}")


@dataclass
class TextFile:
    """One readable file from the extracted tree."""

    path: Path
    relative: str
    text: str

    def lines(self) -> list[str]:
        return self.text.splitlines()


@dataclass
class AndroidArtifacts:
    manifest: AxmlDocument | None = None
    manifest_format: str = ""
    """'binary', 'text' or 'apktool'."""

    dex_files: list[DexFile] = field(default_factory=list)
    resources: ResourceTable | None = None
    signing: SigningInfo | None = None
    native_libs: list[str] = field(default_factory=list)
    archive_names: list[str] = field(default_factory=list)
    jadx_source_root: Path | None = None
    apktool_root: Path | None = None

    def all_dex_strings(self) -> Iterator[tuple[DexFile, int, str]]:
        for dex in self.dex_files:
            for index, value in enumerate(dex.strings):
                yield dex, index, value

    def method_signatures(self) -> set[str]:
        found: set[str] = set()
        for dex in self.dex_files:
            found |= dex.method_signatures()
        return found

    def sites_for_method(self, signature: str):
        for dex in self.dex_files:
            yield from dex.sites_for_method(signature)

    def invocations_by_name(self, method_name: str, receivers: tuple[str, ...] = ()):
        """Invocations of a method name across every DEX in the package."""
        out = []
        for dex in self.dex_files:
            out.extend(dex.invocations_by_name(method_name, receivers))
        return out

    def sites_by_name(self, method_name: str, receivers: tuple[str, ...] = ()):
        return [inv.site for inv in self.invocations_by_name(method_name, receivers)]

    def classes_implementing(self, interface: str):
        out = []
        for dex in self.dex_files:
            out.extend(dex.classes_implementing(interface))
        return out

    def all_classes(self):
        for dex in self.dex_files:
            yield from dex.classes

    def has_any_method(self, *names: str) -> bool:
        wanted = set(names)
        for dex in self.dex_files:
            for ref in dex.method_refs:
                if ref.name in wanted:
                    return True
        return False


@dataclass
class IosArtifacts:
    info_plist: dict = field(default_factory=dict)
    plists: dict[str, dict] = field(default_factory=dict)
    """Relative path -> parsed plist, for every plist in the bundle."""

    binary_path: Path | None = None
    binary_strings: list[str] = field(default_factory=list)
    macho: object | None = None
    """A MachOInfo, or None when the main binary could not be parsed."""

    frameworks: list[str] = field(default_factory=list)
    archive_names: list[str] = field(default_factory=list)
    entitlements: dict = field(default_factory=dict)
    class_names: list[str] = field(default_factory=list)


@dataclass
class ScanContext:
    """Read-only view of one decompiled package, handed to every analyzer."""

    package: PackageInfo
    app: AppInfo
    config: ScanConfig
    root: Path
    """Extraction root inside the sandbox."""

    android: AndroidArtifacts | None = None
    ios: IosArtifacts | None = None
    degraded: list[str] = field(default_factory=list)
    _text_cache: list[TextFile] | None = field(default=None, repr=False)
    _string_cache: list[tuple[str, str]] | None = field(default=None, repr=False)

    @property
    def platform(self) -> Platform:
        return self.package.platform

    @property
    def limits(self):
        return self.config.limits

    def note_degraded(self, message: str) -> None:
        if message not in self.degraded:
            self.degraded.append(message)

    def relative(self, path: Path) -> str:
        try:
            return str(path.relative_to(self.root))
        except ValueError:
            return path.name

    def text_files(self) -> list[TextFile]:
        """Every file small enough and plausibly textual, decoded once and cached."""
        if self._text_cache is not None:
            return self._text_cache

        limits = self.limits
        out: list[TextFile] = []
        for path in iter_files(self.root, limits):
            try:
                size = path.stat().st_size
            except OSError:
                continue
            if size == 0 or size > limits.max_scan_file_bytes:
                continue
            suffix = path.suffix.lower()
            if suffix in _BINARY_SUFFIXES:
                continue
            try:
                raw = path.read_bytes()
            except OSError:
                continue
            if suffix not in _TEXT_SUFFIXES and not _looks_textual(raw):
                continue
            out.append(
                TextFile(
                    path=path,
                    relative=self.relative(path),
                    text=raw.decode("utf-8", "replace"),
                )
            )
        self._text_cache = out
        return out

    def all_strings(self) -> list[tuple[str, str]]:
        """(location, value) for every string the tool recovered, from all sources.

        This is the single surface the secret scanner walks, so a new decompiler
        contributing strings automatically gets covered by every string-based rule.
        """
        if self._string_cache is not None:
            return self._string_cache

        limits = self.limits
        out: list[tuple[str, str]] = []
        budget = limits.max_strings_per_binary

        if self.android:
            for dex in self.android.dex_files:
                for index, value in enumerate(dex.strings):
                    if len(out) >= budget:
                        break
                    if not value:
                        continue
                    sites = dex.string_sites.get(index)
                    location = (
                        sites[0].location if sites else f"{dex.name} (string pool)"
                    )
                    out.append((location, value))
            if self.android.resources:
                for entry in self.android.resources.strings:
                    out.append((entry.location, entry.value))
                for value in self.android.resources.values:
                    if value:
                        out.append(("resources.arsc (value pool)", value))

        if self.ios:
            for value in self.ios.binary_strings[:budget]:
                out.append(("main binary (strings)", value))
            for rel, plist in self.ios.plists.items():
                for key, value in _flatten_plist(plist):
                    out.append((f"{rel}:{key}", value))

        self._string_cache = out
        return out

    def native_strings(self, path: Path, limit: int | None = None) -> list[str]:
        """Printable ASCII runs from a binary file, the `strings(1)` equivalent."""
        cap = limit or self.limits.max_strings_per_binary
        try:
            if path.stat().st_size > self.limits.max_scan_file_bytes:
                return []
            raw = path.read_bytes()
        except OSError:
            return []
        return [m.group().decode("ascii", "replace") for m in _PRINTABLE_RUN.finditer(raw)][:cap]


def _looks_textual(raw: bytes) -> bool:
    """Heuristic used for extension-less files: mostly printable, no NUL run."""
    sample = raw[:8192]
    if b"\x00\x00" in sample:
        return False
    printable = sum(1 for b in sample if 0x20 <= b < 0x7F or b in (9, 10, 13))
    return printable / max(1, len(sample)) > 0.85


def _flatten_plist(value, prefix: str = "") -> Iterator[tuple[str, str]]:
    """Yield (dotted key, string value) for every string a plist contains."""
    if isinstance(value, dict):
        for key, item in value.items():
            child = f"{prefix}.{key}" if prefix else str(key)
            yield from _flatten_plist(item, child)
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            yield from _flatten_plist(item, f"{prefix}[{index}]")
    elif isinstance(value, str):
        yield prefix, value
