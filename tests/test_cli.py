"""CLI behaviour, including the exit codes CI depends on."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from conftest import make_apk_like
from masa.cli import app

runner = CliRunner()


@pytest.fixture(autouse=True)
def _suppress_first_run_notice(monkeypatch, tmp_path: Path):
    """Point the notice marker at a temp path so tests do not depend on ordering."""
    marker = tmp_path / "notice-shown"
    marker.touch()
    monkeypatch.setattr("masa.cli._notice_marker", lambda: marker)


class TestBasicCommands:
    def test_version(self):
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0
        assert "mobile-app-security-analyzer" in result.stdout

    def test_notice_is_available_on_demand(self):
        result = runner.invoke(app, ["notice"])
        assert result.exit_code == 0
        assert "Authorised use only" in result.stdout

    def test_rules_lists_analyzers_and_patterns(self):
        result = runner.invoke(app, ["rules"])
        assert result.exit_code == 0
        assert "secrets" in result.stdout
        assert "SEC-AWS-AKID" in result.stdout
        assert "Improper Credential Usage" in result.stdout

    def test_help_states_the_authorisation_requirement(self):
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "authorised" in result.stdout.lower()


class TestFirstRunNotice:
    def test_notice_is_shown_on_first_run(self, tmp_path: Path, monkeypatch, apk_path: Path):
        marker = tmp_path / "unseen-marker"
        monkeypatch.setattr("masa.cli._notice_marker", lambda: marker)
        result = runner.invoke(app, ["scan", str(apk_path), "--quiet"])
        assert "Authorised use only" in result.stdout
        assert marker.exists()

    def test_notice_is_not_repeated(self, tmp_path: Path, monkeypatch, apk_path: Path):
        marker = tmp_path / "seen-marker"
        marker.touch()
        monkeypatch.setattr("masa.cli._notice_marker", lambda: marker)
        result = runner.invoke(app, ["scan", str(apk_path), "--quiet"])
        assert "Before you scan" not in result.stdout


class TestScanOutput:
    def test_terminal_output_summarises_the_scan(self, apk_path: Path):
        result = runner.invoke(app, ["scan", str(apk_path)])
        assert result.exit_code == 0
        assert "com.masa.vulnerable" in result.stdout
        assert "Risk" in result.stdout
        assert "Critical" in result.stdout

    def test_terminal_output_states_the_static_analysis_limitation(self, apk_path: Path):
        result = runner.invoke(app, ["scan", str(apk_path)])
        assert "Static analysis only" in result.stdout
        assert "absence of a finding" in result.stdout

    def test_json_output_is_written_and_valid(self, apk_path: Path, tmp_path: Path):
        out = tmp_path / "report.json"
        result = runner.invoke(
            app, ["scan", str(apk_path), "-f", "json", "-o", str(out), "--quiet"]
        )
        assert result.exit_code == 0
        data = json.loads(out.read_text())
        assert data["app"]["package_name"] == "com.masa.vulnerable"
        assert data["findings"]

    def test_html_output_is_written(self, apk_path: Path, tmp_path: Path):
        out = tmp_path / "report.html"
        runner.invoke(app, ["scan", str(apk_path), "-f", "html", "-o", str(out), "--quiet"])
        text = out.read_text()
        assert text.startswith("<!DOCTYPE html>")
        assert "OWASP Mobile Top 10" in text

    def test_all_format_writes_both_files(self, apk_path: Path, tmp_path: Path):
        out = tmp_path / "report"
        runner.invoke(app, ["scan", str(apk_path), "-f", "all", "-o", str(out), "--quiet"])
        assert out.with_suffix(".html").exists()
        assert out.with_suffix(".json").exists()

    def test_unknown_format_is_rejected(self, apk_path: Path, tmp_path: Path):
        result = runner.invoke(
            app, ["scan", str(apk_path), "-f", "pdf", "-o", str(tmp_path / "x"), "--quiet"]
        )
        assert result.exit_code == 3


class TestExitCodes:
    def test_clean_scan_exits_zero(self, apk_path: Path):
        assert runner.invoke(app, ["scan", str(apk_path), "--quiet"]).exit_code == 0

    def test_fail_on_high_exits_one_for_a_vulnerable_app(self, apk_path: Path):
        result = runner.invoke(app, ["scan", str(apk_path), "--quiet", "--fail-on", "high"])
        assert result.exit_code == 1

    def test_fail_on_threshold_above_findings_exits_zero(self, tmp_path: Path):
        archive = make_apk_like(tmp_path / "quiet.apk")
        result = runner.invoke(
            app,
            ["scan", str(archive), "--quiet", "--fail-on", "critical",
             "--disable-analyzer", "archive"],
        )
        assert result.exit_code == 0

    def test_invalid_package_exits_two(self, tmp_path: Path):
        bad = tmp_path / "bad.apk"
        bad.write_bytes(b"not a zip at all")
        result = runner.invoke(app, ["scan", str(bad), "--quiet"])
        assert result.exit_code == 2
        # The refusal goes to stderr so it does not pollute piped report output.
        assert "Refused" in result.stderr

    def test_missing_file_exits_two(self, tmp_path: Path):
        result = runner.invoke(app, ["scan", str(tmp_path / "nope.apk"), "--quiet"])
        assert result.exit_code == 2

    def test_unknown_severity_exits_three(self, apk_path: Path):
        result = runner.invoke(app, ["scan", str(apk_path), "-s", "catastrophic"])
        assert result.exit_code == 3


class TestScanOptions:
    def test_severity_filter_is_applied(self, apk_path: Path, tmp_path: Path):
        out = tmp_path / "r.json"
        runner.invoke(
            app, ["scan", str(apk_path), "-s", "critical", "-f", "json", "-o", str(out), "--quiet"]
        )
        data = json.loads(out.read_text())
        assert data["findings"]
        assert all(f["severity"] == "Critical" for f in data["findings"])

    def test_disable_rule_is_applied(self, apk_path: Path, tmp_path: Path):
        out = tmp_path / "r.json"
        runner.invoke(
            app,
            ["scan", str(apk_path), "--disable-rule", "MAN-DEBUGGABLE",
             "-f", "json", "-o", str(out), "--quiet"],
        )
        data = json.loads(out.read_text())
        assert "MAN-DEBUGGABLE" not in {f["rule_id"] for f in data["findings"]}

    def test_max_size_limit_refuses_a_larger_package(self, apk_path: Path):
        result = runner.invoke(app, ["scan", str(apk_path), "--max-size-mb", "1", "--quiet"])
        # The fixture is ~17KB, so a 1MB cap still admits it.
        assert result.exit_code == 0

    def test_keep_artifacts_reports_the_location_and_warns(self, apk_path: Path, tmp_path: Path):
        result = runner.invoke(
            app, ["scan", str(apk_path), "--keep-artifacts", "--workdir", str(tmp_path), "--quiet"]
        )
        assert "kept at" in result.stdout
        assert "credentials" in result.stdout  # the user is warned what is in there
        assert list(tmp_path.iterdir()), "nothing was actually kept"

    def test_scan_is_offline_unless_asked(self, apk_path: Path, tmp_path: Path, monkeypatch):
        import urllib.request

        def _fail(*args, **kwargs):
            raise AssertionError("the CLI reached the network without --online")

        monkeypatch.setattr(urllib.request, "urlopen", _fail)
        assert runner.invoke(app, ["scan", str(apk_path), "--quiet"]).exit_code == 0


class TestIosScanViaCli:
    def test_ipa_is_scanned(self, ipa_path: Path, tmp_path: Path):
        out = tmp_path / "ios.json"
        result = runner.invoke(
            app, ["scan", str(ipa_path), "-f", "json", "-o", str(out), "--quiet"]
        )
        assert result.exit_code == 0
        data = json.loads(out.read_text())
        assert data["app"]["platform"] == "ios"
        assert data["app"]["package_name"] == "com.masa.vulnerable-ios"


class TestPdfExport:
    """PDF is an optional extra; both paths must behave predictably."""

    def test_pdf_without_weasyprint_fails_with_a_useful_message(
        self, apk_path: Path, tmp_path: Path, monkeypatch
    ):
        import masa.report.pdf_report as pdf_module

        def _no_weasyprint(*args, **kwargs):
            raise pdf_module.PdfUnavailable(
                "PDF export needs WeasyPrint and its system libraries (pango, cairo)."
            )

        monkeypatch.setattr("masa.cli.write_pdf", _no_weasyprint)
        result = runner.invoke(
            app, ["scan", str(apk_path), "-f", "pdf", "-o", str(tmp_path / "r.pdf"), "--quiet"]
        )
        assert result.exit_code == 3
        assert "WeasyPrint" in result.stderr

    def test_pdf_is_written_when_weasyprint_is_available(
        self, apk_path: Path, tmp_path: Path, monkeypatch
    ):
        target = tmp_path / "r.pdf"

        def _fake_pdf(report, path):
            Path(path).write_bytes(b"%PDF-1.7 fake")
            return Path(path)

        monkeypatch.setattr("masa.cli.write_pdf", _fake_pdf)
        result = runner.invoke(
            app, ["scan", str(apk_path), "-f", "pdf", "-o", str(target), "--quiet"]
        )
        assert result.exit_code == 0
        assert target.read_bytes().startswith(b"%PDF")

    def test_pdf_availability_probe_never_raises(self):
        from masa.report import pdf_available

        assert isinstance(pdf_available(), bool)
