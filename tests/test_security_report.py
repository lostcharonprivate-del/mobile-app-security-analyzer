"""Security tests for report generation.

Two properties matter here, and both are about the report being a safe artifact
rather than a new attack vector:

* every string in a finding came out of an untrusted package, so the HTML report
  must escape all of it — a report that executed script from the APK it analysed
  would be a delivery mechanism;
* the report is written to be shared, so no credential may appear in it in
  usable form.
"""

from __future__ import annotations

import json
import re
import zipfile
from pathlib import Path

import pytest

from conftest import make_apk_like
from masa.config import ScanConfig
from masa.models import (
    AppInfo,
    Confidence,
    Evidence,
    Finding,
    Platform,
    Report,
    Severity,
)
from masa.report import render_html, render_json
from masa.runner import scan

XSS_PAYLOADS = [
    "<script>alert('xss')</script>",
    "<img src=x onerror=alert(1)>",
    "\"><script>alert(String.fromCharCode(88,83,83))</script>",
    "<svg/onload=alert(1)>",
    "<iframe src='javascript:alert(1)'></iframe>",
    "</title><script>alert(1)</script>",
    "<body onload=alert(1)>",
    "'-alert(1)-'",
    "</style><script>alert(1)</script>",
    "<a href=\"javascript:alert(1)\">click</a>",
    "<!--><script>alert(1)</script>",
]


def _report_with(text: str) -> Report:
    """A report whose every free-text field carries the payload."""
    app = AppInfo(
        platform=Platform.ANDROID,
        file_name=f"{text}.apk",
        file_size=1,
        sha256="0" * 64,
        package_name=text,
        version_name=text,
        permissions=[text],
    )
    finding = Finding(
        rule_id="TEST-XSS",
        title=text,
        severity=Severity.HIGH,
        owasp="M1",
        description=text,
        remediation=text,
        cwe=text,
        analyzer=text,
        references=[text],
        evidence=[Evidence(location=text, line=1, snippet=text)],
    )
    return Report(app=app, findings=[finding], tool_version="test")


class TestHtmlEscaping:
    @pytest.mark.parametrize("payload", XSS_PAYLOADS)
    def test_markup_payloads_are_escaped(self, payload: str):
        html = render_html(_report_with(payload))
        if "<" in payload or '"' in payload or "'" in payload:
            assert payload not in html, "payload survived into the HTML unescaped"
        # It must still be present, just neutralised — dropping it silently
        # would hide evidence from the reader.
        assert "&lt;" in html or "&#" in html

    @pytest.mark.parametrize(
        "scheme_payload",
        ["javascript:alert(1)", "JaVaScRiPt:alert(1)", "data:text/html,<script>alert(1)</script>"],
    )
    def test_dangerous_url_schemes_never_become_links(self, scheme_payload: str):
        """Escaping does not neutralise `javascript:` — it must not become an href."""
        html = render_html(_report_with(scheme_payload))
        assert f'href="{scheme_payload}"' not in html
        assert "href=\"javascript:" not in html.lower()
        assert "href=\"data:" not in html.lower()

    def test_no_script_tag_is_introduced_by_content(self):
        html = render_html(_report_with("<script>alert(1)</script>"))
        body = html.split("</style>", 1)[-1]
        assert "<script" not in body.lower()

    def test_attribute_context_cannot_be_broken_out_of(self):
        """The quote that would end an attribute must be entity-encoded."""
        html = render_html(_report_with('" onmouseover="alert(1)'))
        body = html.split("</style>", 1)[-1]
        # The text may appear as content; what must not appear is an unescaped
        # quote turning it into a live attribute.
        assert '" onmouseover="alert(1)' not in body
        assert "&#34;" in body or "&quot;" in body

    def test_reference_urls_are_escaped_in_href(self):
        html = render_html(_report_with('"><script>alert(1)</script>'))
        assert '"><script>' not in html

    def test_payload_from_a_real_package_is_escaped(self, tmp_path: Path):
        """End-to-end: strings inside an APK reach the report escaped."""
        payload = "<script>alert('apk-xss')</script>"
        archive = make_apk_like(
            tmp_path / "xss.apk",
            {
                "assets/config.properties": f"api_key={payload}AKIA4KJ7XQ2MZLPT9WVC\n".encode(),
                "assets/note.txt": payload.encode(),
            },
        )
        report = scan(archive, ScanConfig()).report
        html = render_html(report)
        body = html.split("</style>", 1)[-1]
        # The payload reaches the report as evidence (partly masked by redaction),
        # but never as live markup.
        assert "<script" not in body.lower()
        assert "apk-xss" in body  # still visible to the reader
        assert "&lt;" in body  # and it got there escaped

    def test_report_has_no_external_references(self):
        """A self-contained report cannot beacon or load remote code."""
        html = render_html(_report_with("plain"))
        body_start = html.find("<body")
        body = html[body_start:]
        for pattern in ("<script src=", "<link rel=\"stylesheet\"", "@import"):
            assert pattern not in body
        # The only http(s) URLs allowed are inside link text and hrefs, which are
        # inert until clicked; nothing may auto-load.
        assert "<iframe" not in body.lower()
        assert "<object" not in body.lower()
        assert "<embed" not in body.lower()


class TestSecretRedaction:
    SECRETS = [
        "AKIA4KJ7XQ2MZLPT9WVC",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "ghp_1A2b3C4d5E6f7G8h9I0jKlMnOpQrStUvWxYz",
        "sk_live_51H8xQ2eZvKYlo2CabcdefghijklmnopqrsTU",
        "AIzaSyD-1mLcVn8Qw3ExAmPlE7kJhGfDsA9zXcV",
        "xoxb-24681357910-24681357911-A1b2C3d4E5f6G7h8I9j0KlMn",
        "hunter2-super-secret-admin",
        "Pr0d_D8_p4ssw0rd_do_not_ship",
    ]

    @pytest.mark.parametrize("secret", SECRETS)
    def test_secret_never_appears_whole_in_the_html_report(self, apk_report, secret):
        html = render_html(apk_report)
        assert secret not in html, f"{secret[:12]}… leaked into the HTML report"

    @pytest.mark.parametrize("secret", SECRETS)
    def test_secret_never_appears_whole_in_the_json_report(self, apk_report, secret):
        payload = render_json(apk_report)
        assert secret not in payload, f"{secret[:12]}… leaked into the JSON report"

    def test_evidence_snippets_are_redacted(self, apk_report):
        for finding in apk_report.findings:
            for evidence in finding.evidence:
                for secret in self.SECRETS:
                    assert secret not in evidence.snippet

    def test_finding_titles_are_redacted(self, apk_report):
        for finding in apk_report.findings:
            for secret in self.SECRETS:
                assert secret not in finding.title

    def test_redacted_form_is_still_identifiable(self, apk_report):
        """A reader must be able to match the finding back to the real value."""
        html = render_html(apk_report)
        assert "AKIA" in html and "****" in html

    def test_metadata_carries_no_raw_secret(self, apk_report):
        for finding in apk_report.findings:
            blob = json.dumps(finding.metadata, default=str)
            for secret in self.SECRETS:
                assert secret not in blob


class TestJsonReport:
    def test_json_is_valid_and_versioned(self, apk_report):
        data = json.loads(render_json(apk_report))
        assert data["schema_version"] == "1.0"
        assert data["tool"]["name"] == "mobile-app-security-analyzer"
        assert isinstance(data["findings"], list)

    def test_every_finding_carries_the_required_fields(self, apk_report):
        data = json.loads(render_json(apk_report))
        for finding in data["findings"]:
            assert finding["rule_id"]
            assert finding["severity"] in ("Critical", "High", "Medium", "Low", "Info")
            assert re.fullmatch(r"M([1-9]|10)", finding["owasp"]["id"])
            assert finding["description"] and finding["remediation"]
            assert "fingerprint" in finding

    def test_owasp_coverage_lists_all_ten_categories(self, apk_report):
        data = json.loads(render_json(apk_report))
        assert len(data["owasp_coverage"]) == 10

    def test_json_round_trips_unicode_safely(self):
        report = _report_with("emoji \U0001f600 and 中文")
        data = json.loads(render_json(report))
        assert "\U0001f600" in data["findings"][0]["title"]
