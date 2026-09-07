"""APK signing scheme detection.

Which schemes an APK is signed with is a security property in itself: a v1-only
APK is exposed to the Janus class of bugs, and a debug certificate in a shipped
build means the signing key is the public one every SDK install shares.

This reads the APK Signing Block directly rather than shelling out to apksigner,
so it works wherever Python does.
"""

from __future__ import annotations

import hashlib
import re
import struct
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

_SIG_BLOCK_MAGIC = b"APK Sig Block 42"
_EOCD_MAGIC = b"PK\x05\x06"
_V2_ID = 0x7109871A
_V3_ID = 0xF05368C0
_V31_ID = 0x1B93AD61
_SOURCE_STAMP_ID = 0x6DFF800D

# Not a signature scheme: apksigner inserts this to 4096-align the signing block.
# It was previously mistaken for a v4 signature, which is why it is named here.
_VERITY_PADDING_ID = 0x42726577

_SCHEME_LABELS = {
    _V2_ID: "v2 (APK Signature Scheme v2)",
    _V3_ID: "v3 (APK Signature Scheme v3)",
    _V31_ID: "v3.1 (APK Signature Scheme v3.1)",
    _SOURCE_STAMP_ID: "SourceStamp",
}

_MAX_SIG_BLOCK = 256 * 1024 * 1024
# X.509 certificates inside a PKCS#7 blob start with this shape: an outer
# SEQUENCE, an inner tbsCertificate SEQUENCE, then [0] EXPLICIT version 2.
_CERT_PREFIX = re.compile(rb"\x30\x82(?P<outer>..)\x30\x82..\xa0\x03\x02\x01\x02", re.S)

# Signature algorithm OIDs, matched against the raw DER of the certificate.
_OIDS = {
    b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x04": ("md5WithRSA", True),
    b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x05": ("sha1WithRSA", True),
    b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b": ("sha256WithRSA", False),
    b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0c": ("sha384WithRSA", False),
    b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0d": ("sha512WithRSA", False),
    b"\x2a\x86\x48\xce\x3d\x04\x03\x02": ("ecdsaWithSHA256", False),
    b"\x2a\x86\x48\xce\x3d\x04\x03\x01": ("ecdsaWithSHA224", False),
}

_DEBUG_MARKERS = (b"Android Debug", b"CN=Android Debug")
_MAX_CERT_BYTES = 4 * 1024 * 1024


@dataclass
class SigningInfo:
    schemes: list[str] = field(default_factory=list)
    v1_only: bool = False
    unsigned: bool = True
    certificates: list[dict[str, object]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, object]:
        return {
            "schemes": list(self.schemes),
            "v1_only": self.v1_only,
            "unsigned": self.unsigned,
            "certificates": list(self.certificates),
        }


def _signing_block_ids(tail: bytes, info: SigningInfo) -> list[int]:
    """Parse the APK Signing Block and return the scheme IDs it actually contains.

    Scanning the file for a 4-byte scheme ID gives false positives — those bytes
    occur by chance in compressed data — so the block's ID-value pairs are walked
    properly instead.
    """
    magic_at = tail.rfind(_SIG_BLOCK_MAGIC)
    if magic_at < 8:
        return []

    # Layout: uint64 size | id-value pairs | uint64 size | 16-byte magic.
    size = struct.unpack_from("<Q", tail, magic_at - 8)[0]
    if size < 24 or size > _MAX_SIG_BLOCK:
        info.warnings.append("APK Signing Block declares an implausible size")
        return []

    block_start = magic_at + len(_SIG_BLOCK_MAGIC) - 8 - size
    if block_start < 0:
        # The block began before the window we read; not an error, just unseen.
        info.warnings.append("APK Signing Block extends past the read window")
        return []
    if struct.unpack_from("<Q", tail, block_start)[0] != size:
        info.warnings.append("APK Signing Block size fields disagree")
        return []

    ids: list[int] = []
    pos = block_start + 8
    pairs_end = magic_at - 8
    while pos + 12 <= pairs_end:
        pair_len = struct.unpack_from("<Q", tail, pos)[0]
        if pair_len < 4 or pos + 8 + pair_len > pairs_end:
            break
        ids.append(struct.unpack_from("<I", tail, pos + 8)[0])
        pos += 8 + pair_len
    return ids


def detect_signing(apk_path: Path, archive_names: list[str]) -> SigningInfo:
    """Determine which signing schemes an APK carries."""
    info = SigningInfo()

    v1_files = [
        n
        for n in archive_names
        if n.upper().startswith("META-INF/")
        and n.upper().endswith((".RSA", ".DSA", ".EC", ".SF"))
    ]
    has_v1 = any(n.upper().endswith((".RSA", ".DSA", ".EC")) for n in v1_files)
    if has_v1:
        info.schemes.append("v1 (JAR signing)")

    try:
        with open(apk_path, "rb") as handle:
            handle.seek(0, 2)
            size = handle.tell()
            # The signing block sits just before the central directory; reading
            # the last 1MB covers every real APK without loading the whole file.
            read_len = min(size, 1024 * 1024)
            handle.seek(size - read_len)
            tail = handle.read(read_len)
    except OSError as exc:
        info.warnings.append(f"could not read APK tail: {exc}")
        tail = b""

    for scheme_id in _signing_block_ids(tail, info):
        label = _SCHEME_LABELS.get(scheme_id)
        if label:
            info.schemes.append(label)

    info.unsigned = not info.schemes
    info.v1_only = has_v1 and not any(
        s.startswith(("v2", "v3")) for s in info.schemes
    )

    # A v4 signature is never stored inside the APK: it lives in a sibling
    # `<name>.apk.idsig` file, so it can only be reported when that file is present.
    if apk_path.with_suffix(apk_path.suffix + ".idsig").exists():
        info.schemes.append("v4 (APK Signature Scheme v4, from sibling .idsig)")

    info.certificates = _read_certificates(apk_path, archive_names, info)
    return info


def _read_certificates(
    apk_path: Path, archive_names: list[str], info: SigningInfo
) -> list[dict[str, object]]:
    """Pull what we can from the PKCS#7 blocks without a full ASN.1 parser."""
    certs: list[dict[str, object]] = []
    cert_names = [
        n
        for n in archive_names
        if n.upper().startswith("META-INF/") and n.upper().endswith((".RSA", ".DSA", ".EC"))
    ]
    if not cert_names:
        return certs

    try:
        with zipfile.ZipFile(apk_path) as archive:
            for name in cert_names[:8]:
                entry = archive.getinfo(name)
                if entry.file_size > _MAX_CERT_BYTES:
                    info.warnings.append(f"{name} is implausibly large; skipped")
                    continue
                raw = archive.read(name)
                certs.append(_describe_certificate(name, raw))
    except (zipfile.BadZipFile, KeyError, OSError) as exc:
        info.warnings.append(f"could not read signing block: {exc}")
    return certs


def _describe_certificate(name: str, raw: bytes) -> dict[str, object]:
    algorithms: list[str] = []
    weak = False
    for oid, (label, is_weak) in _OIDS.items():
        if oid in raw:
            algorithms.append(label)
            weak = weak or is_weak

    der = _extract_certificate_der(raw)
    return {
        "file": name,
        "certificate_sha256": hashlib.sha256(der).hexdigest() if der else "",
        "pkcs7_sha256": hashlib.sha256(raw).hexdigest(),
        "signature_algorithms": sorted(set(algorithms)),
        "weak_signature_algorithm": weak,
        "common_name": _extract_common_name(raw),
        "debug_certificate": any(marker in raw for marker in _DEBUG_MARKERS),
    }


def _extract_certificate_der(raw: bytes) -> bytes:
    """Carve the embedded X.509 certificate out of the PKCS#7 container.

    Matching the certificate's distinctive DER prologue avoids pulling in a full
    ASN.1 library for the one field that matters, and produces exactly the digest
    `apksigner --print-certs` reports.
    """
    match = _CERT_PREFIX.search(raw)
    if not match:
        return b""
    start = match.start()
    body_length = int.from_bytes(match.group("outer"), "big")
    end = start + 4 + body_length
    if end > len(raw):
        return b""
    return raw[start:end]


def _extract_common_name(raw: bytes) -> str:
    """Read the CN attribute value that follows the 2.5.4.3 OID in the DER."""
    cn_oid = b"\x55\x04\x03"
    position = 0
    while True:
        index = raw.find(cn_oid, position)
        if index < 0:
            return ""
        position = index + 3
        if position + 2 > len(raw):
            return ""
        tag = raw[position]
        # PrintableString, UTF8String, IA5String, T61String.
        if tag not in (0x13, 0x0C, 0x16, 0x14):
            continue
        length = raw[position + 1]
        if length & 0x80:  # multi-byte length: CNs are short, so skip these
            continue
        value = raw[position + 2 : position + 2 + length]
        text = value.decode("utf-8", "replace").strip()
        if text:
            return text
