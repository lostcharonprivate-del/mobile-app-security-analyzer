"""Security tests for ingestion: the tool's own attack surface.

Every input here is a package built to attack the analyzer rather than to be
analyzed. The property under test is always the same: the tool refuses or
contains the attack, and never writes outside its sandbox, hangs, or exhausts
the machine.
"""

from __future__ import annotations

import os
import stat
import struct
import zipfile
from dataclasses import replace
from pathlib import Path

import pytest

from conftest import (
    add_raw_member,
    make_apk_like,
    make_ipa_like,
    make_zip_bomb,
    raw_apk_entries,
    write_raw_zip,
)
from masa.config import DEFAULT_LIMITS, ScanConfig
from masa.errors import HostileArchiveError, ValidationError
from masa.ingest.safe_archive import SafeZip
from masa.ingest.sandbox import Sandbox, run_tool
from masa.ingest.validator import validate_package
from masa.runner import scan


# -- zip bombs ---------------------------------------------------------------


class TestZipBomb:
    def test_compression_ratio_is_rejected_before_extraction(self, tmp_path: Path):
        bomb = make_zip_bomb(tmp_path / "bomb.apk", uncompressed_mb=64)
        with SafeZip(bomb) as archive:
            with pytest.raises(HostileArchiveError, match="(?i)ratio|zip bomb"):
                archive.check_bomb()

    def test_bomb_is_rejected_at_validation(self, tmp_path: Path):
        bomb = make_zip_bomb(tmp_path / "bomb.apk", uncompressed_mb=64)
        with pytest.raises(HostileArchiveError):
            validate_package(bomb)

    def test_nothing_is_written_when_a_bomb_is_refused(self, tmp_path: Path):
        bomb = make_zip_bomb(tmp_path / "bomb.apk", uncompressed_mb=64)
        dest = tmp_path / "out"
        with SafeZip(bomb) as archive:
            with pytest.raises(HostileArchiveError):
                archive.extract_all(dest)
        written = list(dest.rglob("*")) if dest.exists() else []
        assert not [p for p in written if p.is_file()], "bomb payload reached the disk"

    def test_total_uncompressed_size_cap(self, tmp_path: Path):
        archive_path = make_apk_like(tmp_path / "big.apk")
        add_raw_member(archive_path, "assets/big.bin", b"\x00" * (8 * 1024 * 1024))
        limits = replace(
            DEFAULT_LIMITS,
            max_total_uncompressed_bytes=1024,
            max_compression_ratio=10_000,
        )
        with SafeZip(archive_path, limits) as archive:
            with pytest.raises(HostileArchiveError, match="uncompressed"):
                archive.check_bomb()

    def test_single_entry_size_cap(self, tmp_path: Path):
        archive_path = make_apk_like(tmp_path / "big.apk")
        add_raw_member(archive_path, "assets/big.bin", b"\x00" * (2 * 1024 * 1024))
        limits = replace(
            DEFAULT_LIMITS,
            max_entry_uncompressed_bytes=1024,
            max_compression_ratio=10_000,
        )
        with SafeZip(archive_path, limits) as archive:
            with pytest.raises(HostileArchiveError, match="limit is 1024"):
                archive.check_bomb()

    def test_entry_count_cap(self, tmp_path: Path):
        archive_path = tmp_path / "many.apk"
        make_apk_like(archive_path)
        with zipfile.ZipFile(archive_path, "a") as archive:
            for index in range(60):
                archive.writestr(f"assets/f{index}.txt", b"x")
        limits = replace(DEFAULT_LIMITS, max_entries=10)
        with SafeZip(archive_path, limits) as archive:
            with pytest.raises(HostileArchiveError, match="entries"):
                archive.check_bomb()

    def test_extraction_byte_budget_stops_a_lying_header(self, tmp_path: Path):
        """A member that expands past its cap is truncated, not written whole."""
        archive_path = make_apk_like(tmp_path / "liar.apk")
        add_raw_member(archive_path, "assets/big.bin", b"\x00" * (4 * 1024 * 1024))
        limits = replace(
            DEFAULT_LIMITS,
            max_extract_bytes=64 * 1024,
            max_compression_ratio=10_000,
            max_total_uncompressed_bytes=1 << 40,
        )
        dest = tmp_path / "out"
        with SafeZip(archive_path, limits) as archive:
            with pytest.raises(HostileArchiveError, match="expanded past"):
                archive.extract_all(dest)
        total = sum(p.stat().st_size for p in dest.rglob("*") if p.is_file())
        assert total <= limits.max_extract_bytes


# -- path traversal ----------------------------------------------------------


TRAVERSAL_NAMES = [
    "../escaped.txt",
    "../../escaped.txt",
    "../../../../../../../../tmp/escaped.txt",
    "a/../../escaped.txt",
    "/etc/escaped.txt",
    "//etc/escaped.txt",
    "C:\\Windows\\escaped.txt",
    "..\\..\\escaped.txt",
    "dir/../../escaped.txt",
]


class TestPathTraversal:
    @pytest.mark.parametrize("name", TRAVERSAL_NAMES)
    def test_traversal_members_are_never_written(self, tmp_path: Path, name: str):
        archive_path = tmp_path / "slip.apk"
        make_apk_like(archive_path)
        add_raw_member(archive_path, name, b"owned")

        root = tmp_path / "root"
        canary = tmp_path / "escaped.txt"
        assert not canary.exists()

        with SafeZip(archive_path) as archive:
            result = archive.extract_all(root)

        assert not canary.exists(), f"{name} escaped the extraction root"
        assert not (tmp_path / "etc").exists()
        # Everything actually written must live under the root.
        for path in root.rglob("*"):
            assert path.resolve().is_relative_to(root.resolve())
        assert any(name in item.name for item in result.skipped)

    @pytest.mark.parametrize("name", TRAVERSAL_NAMES)
    def test_traversal_is_reported_by_validation(self, tmp_path: Path, name: str):
        archive_path = tmp_path / "slip.apk"
        make_apk_like(archive_path)
        add_raw_member(archive_path, name, b"owned")
        info = validate_package(archive_path)
        assert info.unsafe_members, f"{name} was not flagged as unsafe"

    def test_traversal_produces_a_critical_finding(self, tmp_path: Path):
        archive_path = tmp_path / "slip.apk"
        make_apk_like(archive_path)
        add_raw_member(archive_path, "../../owned.txt", b"owned")
        report = scan(archive_path, ScanConfig()).report
        traversal = [f for f in report.findings if f.rule_id == "ARC-UNSAFE-MEMBERS"]
        assert traversal, "a path-traversal member produced no finding"
        assert traversal[0].severity.label == "Critical"

    def test_null_byte_name_injection_does_not_escape(self, tmp_path: Path):
        """A NUL-truncation attack must not place a file outside the root.

        Python's `ZipInfo` truncates a member name at the first NUL before this
        code sees it, so the traversal suffix is discarded upstream rather than
        by our own check. The property that matters is the outcome, so that is
        what is asserted; the name check remains as defence in depth for any
        reader that does not truncate.
        """
        archive_path = write_raw_zip(
            tmp_path / "nul.apk",
            raw_apk_entries([{"name": "good.txt\x00../../evil.txt", "data": b"x"}]),
        )
        root = tmp_path / "root"
        canary = tmp_path / "evil.txt"
        with SafeZip(archive_path) as archive:
            archive.extract_all(root)
        assert not canary.exists()
        assert not list(tmp_path.glob("evil.txt"))
        for path in root.rglob("*"):
            assert path.resolve().is_relative_to(root.resolve())

    def test_control_characters_in_a_name_are_refused(self, tmp_path: Path):
        archive_path = write_raw_zip(
            tmp_path / "ctl.apk",
            raw_apk_entries([{"name": "bad\nname.txt", "data": b"x"}]),
        )
        with SafeZip(archive_path) as archive:
            result = archive.extract_all(tmp_path / "root")
        assert any("control character" in item.reason for item in result.skipped)


# -- symlinks and special files ----------------------------------------------


class TestSymlinkAndSpecialMembers:
    def test_symlink_member_is_never_materialised(self, tmp_path: Path):
        archive_path = tmp_path / "link.apk"
        make_apk_like(archive_path)
        symlink_mode = (stat.S_IFLNK | 0o777) << 16
        add_raw_member(
            archive_path, "evil-link", b"/etc/passwd", external_attr=symlink_mode
        )

        root = tmp_path / "root"
        with SafeZip(archive_path) as archive:
            result = archive.extract_all(root)

        assert not (root / "evil-link").exists()
        assert not (root / "evil-link").is_symlink()
        assert any("symbolic link" in item.reason for item in result.skipped)

    def test_symlink_directory_cannot_redirect_a_later_write(self, tmp_path: Path):
        """The classic two-member attack: a symlink dir, then a file 'inside' it."""
        archive_path = tmp_path / "link2.apk"
        make_apk_like(archive_path)
        target = tmp_path / "outside"
        target.mkdir()
        add_raw_member(
            archive_path, "sneaky", bytes(str(target), "utf-8"),
            external_attr=(stat.S_IFLNK | 0o777) << 16,
        )
        add_raw_member(archive_path, "sneaky/pwned.txt", b"owned")

        root = tmp_path / "root"
        with SafeZip(archive_path) as archive:
            archive.extract_all(root)

        assert not (target / "pwned.txt").exists(), "write was redirected through a symlink"
        assert (root / "sneaky" / "pwned.txt").exists()

    @pytest.mark.parametrize(
        "mode", [stat.S_IFIFO, stat.S_IFCHR, stat.S_IFBLK, stat.S_IFSOCK]
    )
    def test_special_file_members_are_refused(self, tmp_path: Path, mode: int):
        archive_path = tmp_path / "special.apk"
        make_apk_like(archive_path)
        add_raw_member(
            archive_path, "special-node", b"", external_attr=(mode | 0o666) << 16
        )
        with SafeZip(archive_path) as archive:
            result = archive.extract_all(tmp_path / "root")
        assert any("non-regular" in item.reason for item in result.skipped)

    def test_duplicate_member_names_do_not_overwrite(self, tmp_path: Path):
        archive_path = tmp_path / "dup.apk"
        make_apk_like(archive_path)
        add_raw_member(archive_path, "assets/a.txt", b"first")
        add_raw_member(archive_path, "assets/a.txt", b"second")
        root = tmp_path / "root"
        with SafeZip(archive_path) as archive:
            result = archive.extract_all(root)
        assert (root / "assets" / "a.txt").read_bytes() == b"first"
        assert any("duplicate" in item.reason for item in result.skipped)


# -- input validation --------------------------------------------------------


class TestInputValidation:
    def test_extension_is_not_trusted_for_platform_detection(self, tmp_path: Path):
        """An IPA named .apk is still analysed as an IPA, with an anomaly noted."""
        disguised = tmp_path / "actually-an-ipa.apk"
        make_ipa_like(disguised)
        info = validate_package(disguised)
        assert info.platform.value == "ios"
        assert any("extension" in note for note in info.anomalies)

    def test_non_zip_content_is_refused(self, tmp_path: Path):
        fake = tmp_path / "fake.apk"
        fake.write_bytes(b"\x7fELF" + b"\x00" * 4096)
        with pytest.raises(ValidationError, match="ZIP local file header"):
            validate_package(fake)

    def test_zip_that_is_neither_apk_nor_ipa_is_refused(self, tmp_path: Path):
        plain = tmp_path / "plain.apk"
        with zipfile.ZipFile(plain, "w") as archive:
            archive.writestr("readme.txt", b"hello")
        with pytest.raises(ValidationError, match="neither an APK"):
            validate_package(plain)

    def test_empty_file_is_refused(self, tmp_path: Path):
        empty = tmp_path / "empty.apk"
        empty.write_bytes(b"")
        with pytest.raises(ValidationError, match="empty"):
            validate_package(empty)

    def test_oversized_file_is_refused(self, tmp_path: Path):
        archive_path = make_apk_like(tmp_path / "ok.apk")
        limits = replace(DEFAULT_LIMITS, max_input_bytes=10)
        with pytest.raises(ValidationError, match="byte limit"):
            validate_package(archive_path, limits)

    def test_missing_file_is_refused(self, tmp_path: Path):
        with pytest.raises(ValidationError, match="no such file"):
            validate_package(tmp_path / "nope.apk")

    def test_directory_input_is_refused(self, tmp_path: Path):
        with pytest.raises(ValidationError, match="not a regular file"):
            validate_package(tmp_path)

    @pytest.mark.skipif(os.name == "nt", reason="POSIX FIFO")
    def test_fifo_input_is_refused(self, tmp_path: Path):
        fifo = tmp_path / "pipe.apk"
        os.mkfifo(fifo)
        with pytest.raises(ValidationError, match="not a regular file"):
            validate_package(fifo)

    def test_truncated_zip_is_refused_cleanly(self, tmp_path: Path):
        archive_path = make_apk_like(tmp_path / "trunc.apk")
        data = archive_path.read_bytes()
        archive_path.write_bytes(data[: len(data) // 2])
        with pytest.raises(ValidationError):
            validate_package(archive_path)

    def test_encrypted_member_is_skipped_not_fatal(self, tmp_path: Path):
        archive_path = write_raw_zip(
            tmp_path / "enc.apk",
            raw_apk_entries(
                [{"name": "assets/secret.bin", "data": b"encrypted-ish", "flags": 0x1}]
            ),
        )
        with SafeZip(archive_path) as archive:
            result = archive.extract_all(tmp_path / "root")
        assert any("encrypted" in item.reason for item in result.skipped)
        # The rest of the package is still analysed.
        assert (tmp_path / "root" / "AndroidManifest.xml").is_file()

    def test_nested_archive_is_not_recursively_extracted(self, tmp_path: Path):
        inner = tmp_path / "inner.zip"
        with zipfile.ZipFile(inner, "w") as archive:
            archive.writestr("deep/payload.txt", b"nested")
        outer = make_apk_like(tmp_path / "outer.apk")
        add_raw_member(outer, "assets/inner.zip", inner.read_bytes())

        root = tmp_path / "root"
        with SafeZip(outer) as archive:
            archive.extract_all(root)
        assert (root / "assets" / "inner.zip").is_file()
        assert not (root / "assets" / "deep").exists()
        assert not list(root.rglob("payload.txt"))


# -- sandbox -----------------------------------------------------------------


class TestSandbox:
    def test_sandbox_is_private_and_removed(self):
        with Sandbox() as sandbox:
            root = sandbox.root
            assert root is not None
            assert stat.S_IMODE(root.stat().st_mode) == 0o700
        assert not root.exists()

    def test_sandbox_is_removed_even_after_an_error(self):
        root = None
        with pytest.raises(RuntimeError):
            with Sandbox() as sandbox:
                root = sandbox.root
                raise RuntimeError("boom")
        assert root is not None and not root.exists()

    def test_keep_artifacts_preserves_the_tree(self):
        with Sandbox(keep=True) as sandbox:
            root = sandbox.root
            (root / "note.txt").write_text("kept")
        try:
            assert root.exists()
        finally:
            import shutil

            shutil.rmtree(root, ignore_errors=True)

    def test_subdir_rejects_a_traversal_name(self):
        with Sandbox() as sandbox:
            path = sandbox.subdir("../escape")
            assert path.parent == sandbox.root
            assert path.resolve().is_relative_to(sandbox.root.resolve())

    def test_scan_leaves_no_temp_directory_behind(self, tmp_path: Path):
        workdir = tmp_path / "work"
        archive_path = make_apk_like(tmp_path / "ok.apk")
        scan(archive_path, ScanConfig(workdir=workdir))
        leftovers = [p for p in workdir.iterdir()] if workdir.exists() else []
        assert leftovers == [], f"sandbox left behind: {leftovers}"


# -- subprocess containment ---------------------------------------------------


class TestSubprocessContainment:
    def test_arguments_are_never_shell_interpreted(self, tmp_path: Path):
        canary = tmp_path / "pwned.txt"
        result = run_tool(
            ["echo", f"hello; touch {canary}"], cwd=tmp_path
        )
        assert result.ok
        assert not canary.exists(), "argument was interpreted by a shell"
        assert str(canary) in result.stdout  # it was passed through literally

    def test_timeout_kills_the_process(self, tmp_path: Path):
        from dataclasses import replace as _replace

        limits = _replace(DEFAULT_LIMITS, subprocess_timeout_seconds=1)
        result = run_tool(["sleep", "30"], cwd=tmp_path, limits=limits)
        assert result.timed_out
        assert not result.ok
        assert result.duration < 15

    def test_timeout_kills_grandchildren_too(self, tmp_path: Path):
        """A tool that spawns its own children must not leave them running."""
        marker = tmp_path / "still-alive.txt"
        script = tmp_path / "spawner.sh"
        script.write_text(
            "#!/bin/sh\n"
            f"( sleep 8; echo alive > {marker} ) &\n"
            "sleep 30\n"
        )
        script.chmod(0o755)

        from dataclasses import replace as _replace

        limits = _replace(DEFAULT_LIMITS, subprocess_timeout_seconds=1)
        result = run_tool([str(script)], cwd=tmp_path, limits=limits)
        assert result.timed_out

        import time

        time.sleep(10)
        assert not marker.exists(), "a grandchild process survived the timeout"

    def test_missing_tool_is_reported_not_raised(self, tmp_path: Path):
        result = run_tool(["definitely-not-installed-xyzzy"], cwd=tmp_path)
        assert result.not_found
        assert not result.ok

    def test_environment_is_scrubbed(self, tmp_path: Path):
        os.environ["MASA_TEST_SECRET"] = "should-not-propagate"
        try:
            result = run_tool(["env"], cwd=tmp_path)
            assert "MASA_TEST_SECRET" not in result.stdout
            assert "should-not-propagate" not in result.stdout
        finally:
            os.environ.pop("MASA_TEST_SECRET", None)

    def test_empty_command_is_rejected(self, tmp_path: Path):
        with pytest.raises(ValueError):
            run_tool([], cwd=tmp_path)
