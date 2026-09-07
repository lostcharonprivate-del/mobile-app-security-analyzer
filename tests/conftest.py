"""Shared fixtures.

The APK and IPA fixtures are built by the real Android and Apple toolchains
(`build_android_fixture.sh` / `build_ios_fixture.sh`) rather than hand-assembled,
so the parsers are exercised against genuine compiler output. If a prebuilt
fixture is absent and the toolchain is unavailable, the tests that need it skip
rather than fail.
"""

from __future__ import annotations

import os
import shutil
import struct
import subprocess
import zipfile
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"
APK_PATH = FIXTURES / "vulnerable-demo.apk"
IPA_PATH = FIXTURES / "vulnerable-demo.ipa"


def _ensure(path: Path, script: str) -> Path | None:
    if path.exists():
        return path
    builder = FIXTURES / script
    if not builder.exists():
        return None
    try:
        subprocess.run(
            [str(builder)], check=True, capture_output=True, timeout=600
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        return None
    return path if path.exists() else None


@pytest.fixture(scope="session")
def apk_path() -> Path:
    path = _ensure(APK_PATH, "build_android_fixture.sh")
    if path is None:
        pytest.skip("vulnerable-demo.apk is unavailable and the Android SDK is not set up")
    return path


@pytest.fixture(scope="session")
def ipa_path() -> Path:
    path = _ensure(IPA_PATH, "build_ios_fixture.sh")
    if path is None:
        pytest.skip("vulnerable-demo.ipa is unavailable and Xcode is not set up")
    return path


@pytest.fixture(scope="session")
def apk_report(apk_path: Path):
    from masa.config import ScanConfig
    from masa.runner import scan

    return scan(apk_path, ScanConfig()).report


@pytest.fixture(scope="session")
def ipa_report(ipa_path: Path):
    from masa.config import ScanConfig
    from masa.runner import scan

    return scan(ipa_path, ScanConfig()).report


# -- builders for hostile archives -------------------------------------------


def make_apk_like(path: Path, members: dict[str, bytes] | None = None) -> Path:
    """A minimal but structurally valid APK, so validation reaches the stage under test."""
    members = members or {}
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        # A real binary AXML header, enough for platform detection.
        archive.writestr("AndroidManifest.xml", _minimal_axml())
        archive.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 200)
        for name, data in members.items():
            archive.writestr(name, data)
    return path


def make_ipa_like(path: Path, members: dict[str, bytes] | None = None) -> Path:
    members = members or {}
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("Payload/Demo.app/Info.plist", b"bplist00\xd0\x08")
        archive.writestr("Payload/Demo.app/Demo", b"\xcf\xfa\xed\xfe" + b"\x00" * 60)
        for name, data in members.items():
            archive.writestr(name, data)
    return path


def _minimal_axml() -> bytes:
    """Smallest well-formed AXML: RES_XML header plus an empty string pool."""
    pool = struct.pack("<HHIIIIII", 0x0001, 28, 28, 0, 0, 0, 28, 0)
    header = struct.pack("<HHI", 0x0003, 8, 8 + len(pool))
    return header + pool


def add_raw_member(
    path: Path,
    name: str,
    data: bytes,
    external_attr: int | None = None,
    compress: int = zipfile.ZIP_DEFLATED,
) -> None:
    """Append a member, optionally with hand-set Unix mode bits."""
    with zipfile.ZipFile(path, "a", compress) as archive:
        info = zipfile.ZipInfo(name)
        info.compress_type = compress
        info.create_system = 3  # Unix, so external_attr carries the mode
        if external_attr is not None:
            info.external_attr = external_attr
        archive.writestr(info, data)


def make_zip_bomb(path: Path, uncompressed_mb: int = 64) -> Path:
    """A highly compressible payload inside an otherwise valid APK."""
    make_apk_like(path)
    add_raw_member(path, "assets/bomb.bin", b"\x00" * (uncompressed_mb * 1024 * 1024))
    return path


def write_raw_zip(path: Path, entries: list[dict]) -> Path:
    """Build a ZIP byte-by-byte, bypassing every check `zipfile` applies on write.

    Python's writer sanitises exactly the things a hostile archive needs to carry:
    it truncates member names at a NUL and resets the general-purpose flag bits.
    Constructing the container directly is what a real attacker does, and is the
    only way to test the reader against those inputs.

    Each entry accepts: name, data, flags, external_attr, compress ("stored" or
    "deflate"), and declared_uncompressed / declared_compressed to lie in the
    headers about a member's real size.
    """
    import binascii
    import zlib

    local_chunks: list[bytes] = []
    central_chunks: list[bytes] = []
    offset = 0

    for entry in entries:
        raw_name = entry["name"].encode("utf-8", "surrogateescape")
        data = entry.get("data", b"")
        flags = entry.get("flags", 0)
        external_attr = entry.get("external_attr", 0)
        method = 8 if entry.get("compress", "deflate") == "deflate" else 0

        if method == 8:
            compressor = zlib.compressobj(9, zlib.DEFLATED, -15)
            payload = compressor.compress(data) + compressor.flush()
        else:
            payload = data

        crc = binascii.crc32(data) & 0xFFFFFFFF
        declared_uncompressed = entry.get("declared_uncompressed", len(data))
        declared_compressed = entry.get("declared_compressed", len(payload))

        local = struct.pack(
            "<IHHHHHIIIHH",
            0x04034B50, 20, flags, method, 0, 0,
            crc, declared_compressed, declared_uncompressed,
            len(raw_name), 0,
        ) + raw_name + payload
        local_chunks.append(local)

        central_chunks.append(
            struct.pack(
                "<IHHHHHHIIIHHHHHII",
                0x02014B50, 0x031E, 20, flags, method, 0, 0,
                crc, declared_compressed, declared_uncompressed,
                len(raw_name), 0, 0, 0, 0, external_attr, offset,
            )
            + raw_name
        )
        offset += len(local)

    central = b"".join(central_chunks)
    eocd = struct.pack(
        "<IHHHHIIH",
        0x06054B50, 0, 0, len(entries), len(entries), len(central), offset, 0,
    )
    path.write_bytes(b"".join(local_chunks) + central + eocd)
    return path


def raw_apk_entries(extra: list[dict] | None = None) -> list[dict]:
    """The two members that make a raw archive look like an APK, plus extras."""
    entries = [
        {"name": "AndroidManifest.xml", "data": _minimal_axml()},
        {"name": "classes.dex", "data": b"dex\n035\x00" + b"\x00" * 200},
    ]
    entries.extend(extra or [])
    return entries
