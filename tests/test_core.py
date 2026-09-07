"""Core model, scoring, redaction and pipeline behaviour."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from conftest import make_apk_like
from masa.analyzers import all_analyzers, registry_names
from masa.analyzers.base import Analyzer, register
from masa.analyzers.secrets import shannon_entropy
from masa.config import ScanConfig
from masa.models import (
    MASVS_GROUPS,
    OWASP_MOBILE_TOP_10,
    AppInfo,
    Confidence,
    Evidence,
    Finding,
    Platform,
    Report,
    Severity,
)
from masa.patterns import SECRET_RULES, is_structural
from masa.redact import redact_secret, snippet
from masa.runner import scan
from masa.scoring import deduplicate, score_findings, sort_findings


def make_finding(rule_id="R", severity=Severity.HIGH, owasp="M1", **kwargs) -> Finding:
    return Finding(
        rule_id=rule_id, title="t", severity=severity, owasp=owasp,
        description="d", remediation="r", **kwargs
    )


class TestSeverity:
    def test_ordering(self):
        assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW > Severity.INFO

    def test_parse_accepts_name_and_label(self):
        assert Severity.parse("critical") is Severity.CRITICAL
        assert Severity.parse("High") is Severity.HIGH

    def test_parse_rejects_nonsense(self):
        with pytest.raises(ValueError):
            Severity.parse("catastrophic")


class TestFinding:
    def test_invalid_owasp_id_is_rejected(self):
        with pytest.raises(ValueError, match="unknown OWASP"):
            make_finding(owasp="M99")

    def test_invalid_masvs_group_is_rejected(self):
        with pytest.raises(ValueError, match="unknown MASVS"):
            make_finding(masvs="MASVS-NONSENSE")

    def test_fingerprint_is_stable_for_the_same_input(self):
        a = make_finding(evidence=[Evidence("loc", 1, "s")])
        b = make_finding(evidence=[Evidence("loc", 1, "s")])
        assert a.fingerprint == b.fingerprint

    def test_fingerprint_differs_by_location(self):
        a = make_finding(evidence=[Evidence("loc-a")])
        b = make_finding(evidence=[Evidence("loc-b")])
        assert a.fingerprint != b.fingerprint

    def test_serialisation_includes_the_owasp_title(self):
        data = make_finding(owasp="M5").as_dict()
        assert data["owasp"]["title"] == "Insecure Communication"


class TestOwaspCatalogue:
    def test_all_ten_categories_are_defined(self):
        assert list(OWASP_MOBILE_TOP_10) == [f"M{i}" for i in range(1, 11)]

    def test_every_category_has_a_real_description(self):
        for category in OWASP_MOBILE_TOP_10.values():
            assert len(category.description) > 60

    def test_masvs_groups_are_defined(self):
        assert "MASVS-CRYPTO" in MASVS_GROUPS


class TestScoring:
    def test_no_findings_scores_zero(self):
        breakdown = score_findings([])
        assert breakdown.score == 0.0
        assert breakdown.grade == "A"

    def test_score_rises_with_severity(self):
        low = score_findings([make_finding(severity=Severity.LOW)]).score
        high = score_findings([make_finding(severity=Severity.HIGH)]).score
        critical = score_findings([make_finding(severity=Severity.CRITICAL)]).score
        assert low < high < critical

    def test_confidence_reduces_the_contribution(self):
        certain = score_findings([make_finding(confidence=Confidence.HIGH)]).score
        unsure = score_findings([make_finding(confidence=Confidence.LOW)]).score
        assert unsure < certain

    def test_info_findings_do_not_move_the_score(self):
        assert score_findings([make_finding(severity=Severity.INFO)]).score == 0.0

    def test_one_noisy_rule_cannot_dominate(self):
        """Fifty hits of one rule must not outweigh a genuinely broken app."""
        noisy = [
            make_finding(rule_id="SAME", evidence=[Evidence(f"loc{i}")])
            for i in range(50)
        ]
        breakdown = score_findings(noisy)
        assert "SAME" in breakdown.capped_rules
        assert breakdown.raw <= Severity.HIGH.weight * 3

    def test_score_is_bounded(self):
        many = [make_finding(rule_id=f"R{i}", severity=Severity.CRITICAL) for i in range(500)]
        assert 0.0 <= score_findings(many).score <= 100.0

    def test_grades_span_the_range(self):
        grades = {
            score_findings(
                [make_finding(rule_id=f"R{i}", severity=Severity.CRITICAL) for i in range(n)]
            ).grade
            for n in (0, 1, 2, 4, 8, 16)
        }
        assert {"A", "F"} <= grades

    def test_sorting_puts_the_worst_first(self):
        findings = [
            make_finding(rule_id="A", severity=Severity.LOW),
            make_finding(rule_id="B", severity=Severity.CRITICAL),
            make_finding(rule_id="C", severity=Severity.MEDIUM),
        ]
        assert [f.rule_id for f in sort_findings(findings)] == ["B", "C", "A"]

    def test_deduplication_removes_identical_findings(self):
        one = make_finding(evidence=[Evidence("same")])
        two = make_finding(evidence=[Evidence("same")])
        assert len(deduplicate([one, two])) == 1

    def test_deduplication_keeps_distinct_findings(self):
        one = make_finding(evidence=[Evidence("a")])
        two = make_finding(evidence=[Evidence("b")])
        assert len(deduplicate([one, two])) == 2


class TestReportModel:
    def test_grouping_is_in_owasp_order(self):
        report = Report(
            app=AppInfo(),
            findings=[
                make_finding(rule_id="A", owasp="M10"),
                make_finding(rule_id="B", owasp="M2"),
                make_finding(rule_id="C", owasp="M1"),
            ],
        )
        assert list(report.by_owasp()) == ["M1", "M2", "M10"]

    def test_grouping_sorts_by_severity_within_a_category(self):
        report = Report(
            app=AppInfo(),
            findings=[
                make_finding(rule_id="A", owasp="M1", severity=Severity.LOW),
                make_finding(rule_id="B", owasp="M1", severity=Severity.CRITICAL),
            ],
        )
        assert [f.rule_id for f in report.by_owasp()["M1"]] == ["B", "A"]

    def test_severity_counts_cover_every_level(self):
        counts = Report(app=AppInfo()).severity_counts()
        assert set(counts) == {s.label for s in Severity}


class TestRedaction:
    def test_short_values_are_fully_masked(self):
        assert set(redact_secret("abc")) == {"*"}

    def test_long_values_keep_a_recognisable_head_and_tail(self):
        masked = redact_secret("AKIA4KJ7XQ2MZLPT9WVC")
        assert masked.startswith("AKIA") and masked.endswith("VC") and "*" in masked

    def test_empty_input_is_handled(self):
        assert redact_secret("") == ""

    @pytest.mark.parametrize(
        "text",
        [
            "aws key AKIA4KJ7XQ2MZLPT9WVC",
            "password=hunter2-super-secret",
            "user password is hunter2-super-secret",
            "ghp_1A2b3C4d5E6f7G8h9I0jKlMnOpQrStUvWxYz",
            "Bearer AbCdEf1234567890XyZwVuTsRq",
        ],
    )
    def test_credentials_are_masked_in_every_syntactic_shape(self, text: str):
        assert "*" in snippet(text)

    @pytest.mark.parametrize(
        "text",
        [
            "com.masa.vulnerable.MainActivity",
            "AndroidManifest.xml",
            "res/values/strings.xml:db_password",
            "DES/ECB/PKCS5Padding",
            "MODE_WORLD_READABLE",
            "lib/arm64-v8a/libnative.so",
        ],
    )
    def test_structural_strings_are_left_readable(self, text: str):
        assert snippet(text) == text

    def test_snippets_are_length_capped(self):
        assert len(snippet("x" * 5000, limit=100)) <= 100

    def test_newlines_are_collapsed(self):
        assert "\n" not in snippet("a\nb\nc")


class TestEntropyAndPatterns:
    def test_entropy_of_random_text_is_high(self):
        assert shannon_entropy("Zq7X2pLm9Rt4Wv8Ky3Nc6Bd1Hj5Fg0Sa") > 4.3

    def test_entropy_of_repetitive_text_is_low(self):
        assert shannon_entropy("aaaaaaaaaaaaaaaaaaaa") < 1.0

    def test_entropy_of_empty_string_is_zero(self):
        assert shannon_entropy("") == 0.0

    @pytest.mark.parametrize("rule", SECRET_RULES, ids=lambda r: r.id)
    def test_every_pattern_has_a_stable_id_and_severity(self, rule):
        assert re.fullmatch(r"SEC-[A-Z0-9-]+", rule.id)
        assert rule.severity in tuple(Severity)
        assert rule.cwe.startswith("CWE-")

    def test_pattern_ids_are_unique(self):
        ids = [rule.id for rule in SECRET_RULES]
        assert len(ids) == len(set(ids))

    @pytest.mark.parametrize(
        "value,expected",
        [
            ("Lcom/example/Foo;", True),
            ("com.example.MyClass", True),
            ("assets/config.properties", True),
            ("AKIA4KJ7XQ2MZLPT9WVC", False),
            ("Zq7X2pLm9Rt4Wv8Ky3Nc6Bd1Hj5Fg0Sa", False),
        ],
    )
    def test_structural_classification(self, value: str, expected: bool):
        assert is_structural(value) is expected


class TestAnalyzerRegistry:
    def test_every_analyzer_declares_itself(self):
        for analyzer in all_analyzers():
            assert analyzer.name
            assert len(analyzer.description) > 20
            assert analyzer.platforms

    def test_analyzer_names_are_unique(self):
        names = registry_names()
        assert len(names) == len(set(names))

    def test_registering_a_duplicate_name_is_refused(self):
        with pytest.raises(ValueError, match="duplicate"):

            @register
            class Duplicate(Analyzer):
                name = "secrets"

                def analyze(self, ctx):
                    return []

    def test_registering_without_a_name_is_refused(self):
        with pytest.raises(ValueError, match="must define a name"):

            @register
            class Unnamed(Analyzer):
                def analyze(self, ctx):
                    return []


class TestRunnerBehaviour:
    def test_a_failing_analyzer_does_not_lose_the_report(self, tmp_path: Path, monkeypatch):
        """Error containment: one broken rule must not take the scan down."""
        import masa.runner as runner

        class Exploding(Analyzer):
            name = "exploding"
            description = "always raises, to prove containment works"

            def analyze(self, ctx):
                raise RuntimeError("rule is broken")

        original = runner.all_analyzers
        monkeypatch.setattr(runner, "all_analyzers", lambda: [Exploding(), *original()])

        report = scan(make_apk_like(tmp_path / "ok.apk"), ScanConfig()).report
        assert any("exploding" in error for error in report.errors)
        assert report.findings, "other analyzers stopped running"

    def test_disabled_analyzer_is_skipped(self, tmp_path: Path):
        archive = make_apk_like(tmp_path / "ok.apk")
        report = scan(
            archive, ScanConfig(disabled_analyzers=frozenset({"binary"}))
        ).report
        assert not any(f.analyzer == "binary" for f in report.findings)

    def test_disabled_rule_is_suppressed(self, tmp_path: Path):
        archive = make_apk_like(tmp_path / "ok.apk")
        report = scan(
            archive, ScanConfig(disabled_rules=frozenset({"NET-NO-PINNING"}))
        ).report
        assert "NET-NO-PINNING" not in {f.rule_id for f in report.findings}

    def test_severity_floor_filters_findings(self, tmp_path: Path, apk_path: Path):
        report = scan(apk_path, ScanConfig(severity_floor="HIGH")).report
        assert report.findings
        assert all(f.severity.rank >= Severity.HIGH.rank for f in report.findings)

    def test_degraded_coverage_is_surfaced(self, apk_report):
        """Missing optional tooling must be stated, not silently ignored."""
        assert any("apktool" in note or "jadx" in note for note in apk_report.stats.degraded)

    def test_scan_is_deterministic(self, apk_path: Path):
        first = scan(apk_path, ScanConfig()).report
        second = scan(apk_path, ScanConfig()).report
        assert [f.fingerprint for f in first.findings] == [
            f.fingerprint for f in second.findings
        ]
        assert first.risk_score == second.risk_score

    def test_stats_reflect_what_was_examined(self, apk_report):
        assert apk_report.stats.files_scanned > 0
        assert apk_report.stats.strings_extracted > 0
        assert apk_report.stats.duration_seconds >= 0
