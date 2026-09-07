"""Hardened ZIP handling.

Both APKs and IPAs are ZIP archives supplied by an untrusted party, so every read
here assumes the archive is trying to do something hostile. The guarantees this
module enforces:

* no member is ever written outside the extraction root (zip slip / `..` / absolute
  paths / Windows separators / drive letters);
* symlinks, devices, FIFOs and other non-regular members are refused, never
  materialised, so a later write cannot be redirected through one;
* declared and actual sizes are both bounded, and the running total of bytes
  written is checked while streaming, so a lying header cannot fill the disk;
* the overall compression ratio is checked before a single byte is extracted.
"""

from __future__ import annotations

import os
import posixpath
import stat
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

from masa.config import Limits, DEFAULT_LIMITS
from masa.errors import HostileArchiveError, ValidationError

_CHUNK = 256 * 1024

# Characters that have no business appearing in an archive member name.
_FORBIDDEN_NAME_CHARS = frozenset({"\x00", "\r", "\n"})


@dataclass
class MemberReport:
    """Per-entry outcome, so the report can say what was skipped and why."""

    name: str
    reason: str


@dataclass
class ExtractionResult:
    root: Path
    files_written: int = 0
    bytes_written: int = 0
    skipped: list[MemberReport] = field(default_factory=list)

    def skipped_summary(self) -> dict[str, int]:
        summary: dict[str, int] = {}
        for item in self.skipped:
            summary[item.reason] = summary.get(item.reason, 0) + 1
        return summary


def _is_unsafe_name(name: str) -> str | None:
    """Return a reason string if `name` must not be extracted, else None."""
    if not name:
        return "empty member name"
    if any(ch in name for ch in _FORBIDDEN_NAME_CHARS):
        return "control character in member name"
    # ZIP spec says forward slashes; a backslash is either a literal filename
    # character or a Windows-style traversal attempt. Refuse either way.
    if "\\" in name:
        return "backslash in member name"
    if name.startswith("/") or name.startswith("//"):
        return "absolute member path"
    # Drive-letter or UNC style absolute path.
    if len(name) >= 2 and name[1] == ":" and name[0].isalpha():
        return "drive-letter member path"
    parts = name.split("/")
    if any(part == ".." for part in parts):
        return "parent-directory traversal"
    return None


def _member_mode(info: zipfile.ZipInfo) -> int:
    """Unix mode bits recorded by the archive creator, or 0 if none."""
    # create_system 3 == Unix. Mode lives in the high 16 bits of external_attr.
    if info.create_system == 3:
        return info.external_attr >> 16
    return 0


def _member_type_reason(info: zipfile.ZipInfo) -> str | None:
    """Refuse anything that is positively identified as not a file or directory.

    The file-type bits are checked, not the whole mode. Many writers — including
    Python's own `zipfile.writestr` — record permission bits alone (0o600 << 16)
    with no type field at all, and treating that as "not a regular file" would
    skip every member of a large share of real packages.
    """
    mode = _member_mode(info)
    file_type = stat.S_IFMT(mode)
    if file_type == 0:
        # No type recorded. A plain file is the only sane interpretation, and the
        # path checks plus O_NOFOLLOW still constrain what can be written.
        return None
    if file_type == stat.S_IFLNK:
        return "symbolic link member"
    if file_type in (stat.S_IFREG, stat.S_IFDIR):
        return None
    return "non-regular member (device/fifo/socket)"


class SafeZip:
    """A `zipfile.ZipFile` wrapper that refuses to do anything dangerous."""

    def __init__(self, path: Path, limits: Limits = DEFAULT_LIMITS) -> None:
        self.path = Path(path)
        self.limits = limits
        try:
            self._zip = zipfile.ZipFile(self.path)
        except zipfile.BadZipFile as exc:
            raise ValidationError(f"not a readable ZIP archive: {exc}") from exc

    def __enter__(self) -> "SafeZip":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def close(self) -> None:
        self._zip.close()

    # -- inspection -----------------------------------------------------------

    def infolist(self) -> list[zipfile.ZipInfo]:
        return self._zip.infolist()

    def namelist(self) -> list[str]:
        return self._zip.namelist()

    def has_entry(self, name: str) -> bool:
        try:
            self._zip.getinfo(name)
            return True
        except KeyError:
            return False

    def check_bomb(self) -> None:
        """Validate declared sizes and compression ratio before extracting anything.

        Raises HostileArchiveError when the archive's own central directory already
        shows it cannot be safely unpacked.
        """
        limits = self.limits
        infos = self._zip.infolist()
        if len(infos) > limits.max_entries:
            raise HostileArchiveError(
                f"archive declares {len(infos)} entries, limit is {limits.max_entries}"
            )

        total_uncompressed = 0
        total_compressed = 0
        for info in infos:
            if info.file_size > limits.max_entry_uncompressed_bytes:
                raise HostileArchiveError(
                    f"entry {info.filename!r} declares {info.file_size} bytes, "
                    f"limit is {limits.max_entry_uncompressed_bytes}"
                )
            total_uncompressed += info.file_size
            total_compressed += info.compress_size
            if total_uncompressed > limits.max_total_uncompressed_bytes:
                raise HostileArchiveError(
                    f"archive declares more than {limits.max_total_uncompressed_bytes} "
                    "bytes uncompressed"
                )

        # A ratio check on a handful of kilobytes says nothing useful; a 1000:1
        # ratio across gigabytes is the classic bomb signature.
        if (
            total_uncompressed >= limits.min_ratio_check_bytes
            and total_compressed > 0
        ):
            ratio = total_uncompressed / total_compressed
            if ratio > limits.max_compression_ratio:
                raise HostileArchiveError(
                    f"compression ratio {ratio:.0f}:1 exceeds limit of "
                    f"{limits.max_compression_ratio:.0f}:1 (zip bomb)"
                )

    def unsafe_members(self) -> list[MemberReport]:
        """Every member that would be refused, with the reason. Used by validation."""
        reports: list[MemberReport] = []
        for info in self._zip.infolist():
            reason = _is_unsafe_name(info.filename) or _member_type_reason(info)
            if reason:
                reports.append(MemberReport(info.filename, reason))
        return reports

    def read_member(self, name: str, max_bytes: int | None = None) -> bytes:
        """Read one member into memory with a hard byte cap.

        Used for small, known files (manifest, plists) that we parse without
        writing to disk first.
        """
        cap = max_bytes if max_bytes is not None else self.limits.max_scan_file_bytes
        try:
            info = self._zip.getinfo(name)
        except KeyError as exc:
            raise ValidationError(f"archive has no member {name!r}") from exc
        if info.file_size > cap:
            raise HostileArchiveError(
                f"member {name!r} declares {info.file_size} bytes, cap is {cap}"
            )
        with self._zip.open(info) as handle:
            data = handle.read(cap + 1)
        if len(data) > cap:
            raise HostileArchiveError(
                f"member {name!r} expanded past its {cap} byte cap"
            )
        return data

    # -- extraction -----------------------------------------------------------

    def extract_all(self, dest: Path) -> ExtractionResult:
        """Stream every safe member into `dest`, enforcing limits as we write."""
        self.check_bomb()
        root = Path(dest).resolve()
        root.mkdir(parents=True, exist_ok=True)
        result = ExtractionResult(root=root)
        limits = self.limits

        for info in self._zip.infolist():
            reason = _is_unsafe_name(info.filename) or _member_type_reason(info)
            if reason:
                result.skipped.append(MemberReport(info.filename, reason))
                continue

            # Encrypted members cannot be read without a password; note and skip
            # rather than raising, so the rest of the package still gets analysed.
            if info.flag_bits & 0x1:
                result.skipped.append(MemberReport(info.filename, "encrypted member"))
                continue

            normalised = posixpath.normpath(info.filename)
            if normalised in (".", "/") or normalised.startswith(".."):
                result.skipped.append(
                    MemberReport(info.filename, "parent-directory traversal")
                )
                continue

            target = (root / normalised).resolve()
            if not _contains(root, target):
                result.skipped.append(
                    MemberReport(info.filename, "resolves outside extraction root")
                )
                continue

            if info.is_dir() or info.filename.endswith("/"):
                target.mkdir(parents=True, exist_ok=True)
                continue

            if result.bytes_written >= limits.max_extract_bytes:
                result.skipped.append(
                    MemberReport(info.filename, "extraction byte budget exhausted")
                )
                continue

            target.parent.mkdir(parents=True, exist_ok=True)
            # Re-check containment after creating parents: a component could be a
            # pre-existing symlink only if something else put it there, but the
            # cost of checking is nil compared with the cost of being wrong.
            if not _contains(root, target.parent.resolve()):
                result.skipped.append(
                    MemberReport(info.filename, "parent resolves outside root")
                )
                continue

            written = self._stream_member(info, target, result, limits)
            if written is None:
                continue
            result.files_written += 1
            result.bytes_written += written

        return result

    def _stream_member(
        self,
        info: zipfile.ZipInfo,
        target: Path,
        result: ExtractionResult,
        limits: Limits,
    ) -> int | None:
        """Copy one member to disk, stopping the moment it exceeds a budget."""
        entry_cap = min(
            limits.max_entry_uncompressed_bytes,
            limits.max_extract_bytes - result.bytes_written,
        )
        written = 0
        # O_NOFOLLOW: never write through a symlink. O_EXCL: never overwrite an
        # entry a previous member already created (duplicate-name attacks).
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(target, flags, 0o600)
        except FileExistsError:
            result.skipped.append(MemberReport(info.filename, "duplicate member name"))
            return None
        except OSError as exc:
            result.skipped.append(
                MemberReport(info.filename, f"could not create file: {exc.strerror}")
            )
            return None

        try:
            with os.fdopen(fd, "wb") as out, self._zip.open(info) as src:
                while True:
                    chunk = src.read(_CHUNK)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > entry_cap:
                        raise HostileArchiveError(
                            f"member {info.filename!r} expanded past {entry_cap} bytes "
                            "(declared size was a lie)"
                        )
                    out.write(chunk)
        except HostileArchiveError:
            target.unlink(missing_ok=True)
            raise
        except (zipfile.BadZipFile, OSError, EOFError) as exc:
            target.unlink(missing_ok=True)
            result.skipped.append(
                MemberReport(info.filename, f"unreadable member: {type(exc).__name__}")
            )
            return None
        return written


def _contains(root: Path, candidate: Path) -> bool:
    """True when `candidate` is `root` or lives underneath it."""
    try:
        return candidate == root or candidate.is_relative_to(root)
    except (ValueError, OSError):
        return False


def iter_files(root: Path, limits: Limits = DEFAULT_LIMITS) -> Iterator[Path]:
    """Walk an already-extracted tree, refusing to follow symlinks out of it."""
    root = root.resolve()
    count = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        current = Path(dirpath)
        # Prune any directory symlink that slipped in from a non-archive source.
        dirnames[:] = [d for d in dirnames if not (current / d).is_symlink()]
        for name in filenames:
            path = current / name
            if path.is_symlink():
                continue
            if not _contains(root, path.resolve()):
                continue
            count += 1
            if count > limits.max_scanned_files:
                return
            yield path
