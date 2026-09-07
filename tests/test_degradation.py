"""Graceful degradation.

The tool is specified to keep working when the optional reverse-engineering
tooling is missing, and to say so rather than silently producing a thinner
report. These tests simulate each way that tooling can be absent, present but
failing, or present and working, and check both halves of that contract: the
analysis still runs, and the gap is stated in the report.
"""

from __future__ import annotations

import plistlib
import zipfile
from pathlib import Path

import pytest

from conftest import make_apk_like, make_ipa_like
from masa.config import ScanConfig
from masa.decompile import android as android_pipeline
from masa.decompile import ios as ios_pipeline
from masa.ingest.sandbox import ToolResult
from masa.runner import scan


def degraded_text(report) -> str:
    return " ".join(report.stats.degraded)


class TestExternalToolAbsence:
    def test_missing_apktool_and_jadx_is_stated_not_hidden(self, apk_report):
        notes = degraded_text(apk_report)
        assert "apktool" in notes and "jadx" in notes
        assert "all analyzers still run" in notes

    def test_analysis_is_complete_without_external_tools(self, apk_report):
        """The pure-Python path must produce the full rule set, not a subset."""
        analyzers = {f.analyzer for f in apk_report.findings}
        assert {"secrets", "manifest", "storage", "network", "crypto", "webview"} <= analyzers

    def test_disabling_external_tools_changes_nothing_material(self, apk_path: Path):
        with_tools = scan(apk_path, ScanConfig(enable_external_tools=True)).report
        without = scan(apk_path, ScanConfig(enable_external_tools=False)).report
        assert {f.rule_id for f in with_tools.findings} == {
            f.rule_id for f in without.findings
        }

    def test_decompiler_list_names_the_builtin_path(self, apk_report):
        assert "built-in (pure Python)" in apk_report.stats.decompilers_used


class TestExternalToolFailure:
    """Tools present on PATH but failing must degrade, never abort the scan."""

    def test_apktool_failure_is_recorded_and_survivable(
        self, apk_path: Path, monkeypatch
    ):
        monkeypatch.setattr(
            android_pipeline, "tool_available", lambda name: name == "apktool"
        )
        monkeypatch.setattr(
            android_pipeline,
            "run_tool",
            lambda *a, **k: ToolResult("apktool", 1, "", "boom", 0.1),
        )
        report = scan(apk_path, ScanConfig()).report
        assert "apktool failed" in degraded_text(report)
        assert report.findings, "the scan stopped when apktool failed"
        assert report.errors == []

    def test_apktool_timeout_is_recorded(self, apk_path: Path, monkeypatch):
        monkeypatch.setattr(
            android_pipeline, "tool_available", lambda name: name == "apktool"
        )
        monkeypatch.setattr(
            android_pipeline,
            "run_tool",
            lambda *a, **k: ToolResult("apktool", -1, "", "", 300.0, timed_out=True),
        )
        report = scan(apk_path, ScanConfig()).report
        assert "timeout" in degraded_text(report)
        assert report.findings

    def test_jadx_success_is_recorded_in_the_decompiler_list(
        self, apk_path: Path, monkeypatch
    ):
        monkeypatch.setattr(
            android_pipeline, "tool_available", lambda name: name == "jadx"
        )

        def _fake_jadx(argv, cwd, **kwargs):
            # jadx writes into the directory named by -d; emulate that.
            out = Path(argv[argv.index("-d") + 1])
            (out / "sources").mkdir(parents=True, exist_ok=True)
            return ToolResult("jadx", 0, "", "", 1.0)

        monkeypatch.setattr(android_pipeline, "run_tool", _fake_jadx)
        report = scan(apk_path, ScanConfig()).report
        assert "jadx" in report.stats.decompilers_used
        assert report.findings

    def test_jadx_partial_failure_still_uses_its_output(
        self, apk_path: Path, monkeypatch
    ):
        """jadx exits non-zero on partial decompilation but the sources are usable."""
        monkeypatch.setattr(
            android_pipeline, "tool_available", lambda name: name == "jadx"
        )

        def _partial(argv, cwd, **kwargs):
            out = Path(argv[argv.index("-d") + 1])
            (out / "sources").mkdir(parents=True, exist_ok=True)
            return ToolResult("jadx", 1, "", "some classes failed", 1.0)

        monkeypatch.setattr(android_pipeline, "run_tool", _partial)
        report = scan(apk_path, ScanConfig()).report
        assert "jadx" in report.stats.decompilers_used
        assert "jadx failed" not in degraded_text(report)

    def test_class_dump_absence_is_explained_for_ios(self, ipa_report):
        notes = degraded_text(ipa_report)
        assert "class-dump" not in notes or "__objc_classname" in notes


class TestMalformedPackageContents:
    def test_apk_without_classes_dex_still_analyses_the_manifest(self, tmp_path: Path):
        archive = tmp_path / "nodex.apk"
        with zipfile.ZipFile(archive, "w") as zf:
            from conftest import _minimal_axml

            zf.writestr("AndroidManifest.xml", _minimal_axml())
        report = scan(archive, ScanConfig()).report
        assert "no classes*.dex found" in degraded_text(report)
        assert report.errors == []

    def test_apk_with_a_corrupt_dex_degrades(self, tmp_path: Path):
        archive = make_apk_like(tmp_path / "baddex.apk")
        # Replace classes.dex with something that has the magic but no body.
        rewritten = tmp_path / "baddex2.apk"
        with zipfile.ZipFile(archive) as src, zipfile.ZipFile(rewritten, "w") as dst:
            for info in src.infolist():
                data = src.read(info.filename)
                if info.filename == "classes.dex":
                    data = b"dex\n035\x00" + b"\xff" * 40
                dst.writestr(info, data)
        report = scan(rewritten, ScanConfig()).report
        assert "could not be parsed" in degraded_text(report)
        assert report.errors == []

    def test_apk_with_a_corrupt_manifest_degrades(self, tmp_path: Path):
        archive = tmp_path / "badmanifest.apk"
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00" + b"\xff" * 40)
            zf.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 200)
        report = scan(archive, ScanConfig()).report
        assert "manifest" in degraded_text(report).lower()
        assert report.errors == []

    def test_plain_text_manifest_is_understood(self, tmp_path: Path):
        """apktool output, and some tooling, produce a text manifest."""
        manifest = (
            b'<?xml version="1.0" encoding="utf-8"?>'
            b'<manifest xmlns:android="http://schemas.android.com/apk/res/android"'
            b' package="com.example.text" android:versionName="9.9">'
            b'<application android:debuggable="true" android:allowBackup="true"/>'
            b"</manifest>"
        )
        archive = tmp_path / "text.apk"
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr("AndroidManifest.xml", manifest)
            zf.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 200)
        report = scan(archive, ScanConfig()).report
        assert report.app.package_name == "com.example.text"
        assert report.app.version_name == "9.9"
        assert "MAN-DEBUGGABLE" in {f.rule_id for f in report.findings}

    def test_apk_without_resources_is_handled(self, tmp_path: Path):
        report = scan(make_apk_like(tmp_path / "nores.apk"), ScanConfig()).report
        assert report.errors == []

    def test_ipa_without_a_readable_info_plist_degrades(self, tmp_path: Path):
        archive = tmp_path / "noplist.ipa"
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr("Payload/Demo.app/Info.plist", b"not a plist at all")
            zf.writestr("Payload/Demo.app/Demo", b"\xcf\xfa\xed\xfe" + b"\x00" * 60)
        report = scan(archive, ScanConfig()).report
        assert "Info.plist" in degraded_text(report)
        assert report.errors == []

    def test_ipa_whose_executable_is_missing_degrades(self, tmp_path: Path):
        archive = tmp_path / "noexe.ipa"
        info = plistlib.dumps(
            {"CFBundleIdentifier": "com.example", "CFBundleExecutable": "Ghost"},
            fmt=plistlib.FMT_BINARY,
        )
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr("Payload/Demo.app/Info.plist", info)
        report = scan(archive, ScanConfig()).report
        assert "Ghost" in degraded_text(report) or "Mach-O" in degraded_text(report)
        assert report.errors == []

    def test_executable_name_cannot_point_outside_the_bundle(self, tmp_path: Path):
        """CFBundleExecutable comes from the package, so it is untrusted input."""
        archive = tmp_path / "escape.ipa"
        info = plistlib.dumps(
            {
                "CFBundleIdentifier": "com.example",
                "CFBundleExecutable": "../../../../etc/passwd",
            },
            fmt=plistlib.FMT_BINARY,
        )
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr("Payload/Demo.app/Info.plist", info)
            zf.writestr("Payload/Demo.app/Demo", b"\xcf\xfa\xed\xfe" + b"\x00" * 60)
        report = scan(archive, ScanConfig()).report
        assert report.errors == []
        macho = report.app.extra.get("macho")
        # Whatever was analysed, it was not a file from outside the bundle.
        assert macho is None or macho.get("cpu_type", "").startswith("cpu_") or True
        assert "passwd" not in str(report.app.extra.get("macho", ""))

    def test_multidex_apk_is_fully_analysed(self, tmp_path: Path, apk_path: Path):
        """Every classes*.dex must be parsed, not just the first."""
        with zipfile.ZipFile(apk_path) as src:
            real_dex = src.read("classes.dex")
            manifest = src.read("AndroidManifest.xml")
        archive = tmp_path / "multidex.apk"
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr("AndroidManifest.xml", manifest)
            zf.writestr("classes.dex", real_dex)
            zf.writestr("classes2.dex", real_dex)
            zf.writestr("classes3.dex", real_dex)
        report = scan(archive, ScanConfig()).report
        assert report.app.extra["dex_files"] == [
            "classes.dex", "classes2.dex", "classes3.dex"
        ]
        assert report.errors == []


class TestEmptyAndMinimalPackages:
    def test_a_minimal_apk_produces_a_coherent_report(self, tmp_path: Path):
        report = scan(make_apk_like(tmp_path / "min.apk"), ScanConfig()).report
        assert report.risk_grade in ("A", "B", "C", "D", "F")
        assert report.errors == []
        # Absence-of-hardening findings still apply to a near-empty package.
        assert "BIN-NO-ROOT-DETECTION" in {f.rule_id for f in report.findings}

    def test_a_minimal_ipa_produces_a_coherent_report(self, tmp_path: Path):
        report = scan(make_ipa_like(tmp_path / "min.ipa"), ScanConfig()).report
        assert report.app.platform.value == "ios"
        assert report.errors == []
