"""Package validation: decide what a file actually *is*, before touching it.

The extension is treated as a hint and nothing more. Platform detection reads the
archive's own structure, and every safety limit is checked before the pipeline is
allowed to unpack anything.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path

from masa.config import Limits, DEFAULT_LIMITS
from masa.errors import ValidationError
from masa.ingest.safe_archive import SafeZip, MemberReport
from masa.models import Platform

# Local file header. An APK/IPA always starts with one; an empty or spanned
# archive (PK\x05\x06 / PK\x07\x08) is not a valid package.
_ZIP_MAGIC = b"PK\x03\x04"

_ANDROID_MANIFEST = "AndroidManifest.xml"
_IPA_APP_RE = re.compile(r"^Payload/([^/]+\.app)/")

_HASH_CHUNK = 1024 * 1024


@dataclass
class PackageInfo:
    """What validation concluded about the input file."""

    path: Path
    platform: Platform
    size: int
    sha256: str
    file_name: str
    app_bundle: str | None = None
    """For IPAs: the `Payload/Name.app` directory."""

    unsafe_members: list[MemberReport] = field(default_factory=list)
    """Members that will be refused at extraction time. Non-empty means the
    archive itself is doing something it shouldn't — worth reporting as a finding."""

    anomalies: list[str] = field(default_factory=list)
    """Non-fatal oddities: extension/content mismatch, both platforms' markers, etc."""

    entry_count: int = 0


def _stat_regular_file(path: Path) -> os.stat_result:
    try:
        info = path.stat()  # follows symlinks: a symlink to a real file is fine
    except FileNotFoundError as exc:
        raise ValidationError(f"no such file: {path}") from exc
    except OSError as exc:
        raise ValidationError(f"cannot stat {path}: {exc.strerror}") from exc
    if not stat.S_ISREG(info.st_mode):
        raise ValidationError(
            f"{path} is not a regular file (refusing device, FIFO or directory input)"
        )
    return info


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while chunk := handle.read(_HASH_CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def detect_platform(archive: SafeZip) -> tuple[Platform, str | None, list[str]]:
    """Identify the package from archive structure alone.

    Returns (platform, app_bundle_dir, anomalies).
    """
    anomalies: list[str] = []
    names = archive.namelist()

    has_manifest = _ANDROID_MANIFEST in names
    has_dex = any(
        n == "classes.dex" or re.fullmatch(r"classes\d+\.dex", n) for n in names
    )

    app_bundle: str | None = None
    for name in names:
        match = _IPA_APP_RE.match(name)
        if match:
            app_bundle = f"Payload/{match.group(1)}"
            break

    if has_manifest and app_bundle:
        # Genuinely unusual: one of the two markers is decoration. Prefer the
        # Android marker (a root AndroidManifest.xml is a much stronger signal)
        # but say so loudly in the report.
        anomalies.append(
            "archive contains both a root AndroidManifest.xml and a Payload/*.app "
            "bundle; analysed as Android"
        )
        return Platform.ANDROID, None, anomalies

    if has_manifest:
        if not has_dex:
            anomalies.append(
                "APK has an AndroidManifest.xml but no classes.dex "
                "(resource-only split APK, or a stripped package)"
            )
        return Platform.ANDROID, None, anomalies

    if app_bundle:
        return Platform.IOS, app_bundle, anomalies

    raise ValidationError(
        "file is a ZIP archive but neither an APK (no root AndroidManifest.xml) "
        "nor an IPA (no Payload/*.app directory)"
    )


def validate_package(
    path: str | os.PathLike[str], limits: Limits = DEFAULT_LIMITS
) -> PackageInfo:
    """Full pre-flight check. Raises ValidationError/HostileArchiveError on refusal."""
    path = Path(path)
    info = _stat_regular_file(path)

    if info.st_size == 0:
        raise ValidationError(f"{path} is empty")
    if info.st_size > limits.max_input_bytes:
        raise ValidationError(
            f"{path} is {info.st_size} bytes, above the "
            f"{limits.max_input_bytes} byte limit"
        )

    with open(path, "rb") as handle:
        magic = handle.read(4)
    if magic != _ZIP_MAGIC:
        raise ValidationError(
            "file does not start with a ZIP local file header; APKs and IPAs are "
            f"ZIP archives (saw {magic!r})"
        )

    with SafeZip(path, limits) as archive:
        archive.check_bomb()
        platform, app_bundle, anomalies = detect_platform(archive)
        unsafe = archive.unsafe_members()
        entry_count = len(archive.infolist())

    suffix = path.suffix.lower()
    expected = {Platform.ANDROID: ".apk", Platform.IOS: ".ipa"}[platform]
    if suffix != expected:
        anomalies.append(
            f"file extension {suffix or '(none)'} does not match detected "
            f"{platform.value} package (expected {expected}); analysed by content"
        )

    return PackageInfo(
        path=path,
        platform=platform,
        size=info.st_size,
        sha256=sha256_file(path),
        file_name=path.name,
        app_bundle=app_bundle,
        unsafe_members=unsafe,
        anomalies=anomalies,
        entry_count=entry_count,
    )
