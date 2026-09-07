"""Android detection correctness against the compiled vulnerable fixture.

The fixture is built by aapt2/d8/apksigner from source in `tests/fixtures/android_src`,
so these assert against genuine compiler output rather than hand-made bytes. That
source also contains `SecureHelper`, which uses the same APIs correctly — the
false-positive controls check that nothing in that class is ever reported.
"""

from __future__ import annotations

import re
import zipfile
from pathlib import Path

import pytest

from masa.decompile.apksig import detect_signing
from masa.decompile.arsc import parse_arsc
from masa.decompile.axml import parse_axml
from masa.decompile.dex import parse_dex


def rule_ids(report) -> set[str]:
    return {finding.rule_id for finding in report.findings}


def finding_for(report, rule_id: str):
    matches = [f for f in report.findings if f.rule_id == rule_id]
    assert matches, f"{rule_id} did not fire"
    return matches[0]


def evidence_locations(report, rule_id: str) -> set[str]:
    return {
        evidence.location
        for finding in report.findings
        if finding.rule_id == rule_id
        for evidence in finding.evidence
    }


class TestAppMetadata:
    def test_package_metadata_is_recovered(self, apk_report):
        app = apk_report.app
        assert app.package_name == "com.masa.vulnerable"
        assert app.version_name == "1.3.7"
        assert app.version_code == "42"
        assert app.min_sdk == "21"
        assert app.target_sdk == "34"

    def test_permissions_are_listed(self, apk_report):
        assert "android.permission.READ_SMS" in apk_report.app.permissions
        assert "android.permission.INTERNET" in apk_report.app.permissions
        assert len(apk_report.app.permissions) == 9

    def test_components_are_enumerated(self, apk_report):
        components = apk_report.app.components
        assert len(components["activity"]) == 3
        assert len(components["provider"]) == 2
        assert all(c["exported"] for c in components["service"])

    def test_signing_information_is_recovered(self, apk_report):
        signing = apk_report.app.signing
        assert any("v1" in scheme for scheme in signing["schemes"])
        assert any("v2" in scheme for scheme in signing["schemes"])
        assert signing["unsigned"] is False
        assert signing["certificates"][0]["common_name"] == "MASA Test Fixture"

    def test_scan_reports_no_internal_errors(self, apk_report):
        assert apk_report.errors == []


class TestSecretDetection:
    @pytest.mark.parametrize(
        "rule_id",
        [
            "SEC-AWS-AKID", "SEC-AWS-SECRET", "SEC-GITHUB-PAT", "SEC-STRIPE",
            "SEC-GCP-APIKEY", "SEC-SLACK-TOKEN", "SEC-JWT", "SEC-PRIVATE-KEY",
            "SEC-NAMED-RESOURCE", "SEC-ENTROPY",
        ],
    )
    def test_expected_secret_rules_fire(self, apk_report, rule_id: str):
        assert rule_id in rule_ids(apk_report)

    def test_secret_in_a_string_resource_is_located_precisely(self, apk_report):
        locations = evidence_locations(apk_report, "SEC-GCP-APIKEY")
        assert any("strings.xml:google_api_key" in loc for loc in locations)

    def test_secret_in_bytecode_is_attributed_to_its_field(self, apk_report):
        locations = evidence_locations(apk_report, "SEC-GITHUB-PAT")
        assert any("MainActivity.GITHUB_TOKEN" in loc for loc in locations)

    def test_secret_in_an_asset_file_is_located(self, apk_report):
        locations = evidence_locations(apk_report, "SEC-AWS-SECRET")
        assert any("assets/config.properties" in loc for loc in locations)

    def test_aws_documentation_example_key_is_not_reported(self, apk_report):
        """AKIAIOSFODNN7EXAMPLE appears in AWS's own docs; it is not a credential."""
        for finding in apk_report.findings:
            for evidence in finding.evidence:
                assert "AKIAIOSFODNN7EXAMPLE" not in evidence.snippet
            assert "IOSFODNN7EXAMPLE" not in finding.title


class TestManifestAnalyzer:
    def test_debuggable_is_critical(self, apk_report):
        finding = finding_for(apk_report, "MAN-DEBUGGABLE")
        assert finding.severity.label == "Critical"
        assert finding.owasp == "M8"
        assert finding.cwe == "CWE-489"

    def test_allow_backup_is_reported(self, apk_report):
        assert finding_for(apk_report, "MAN-ALLOW-BACKUP").owasp == "M8"

    def test_exported_activities_exclude_the_launcher(self, apk_report):
        """MainActivity is the launcher, so only the other two count."""
        finding = finding_for(apk_report, "MAN-EXPORTED-ACTIVITY")
        assert finding.metadata["count"] == 2
        snippets = " ".join(e.snippet for e in finding.evidence)
        assert "MainActivity" not in snippets
        assert "DeepLinkActivity" in snippets and "AdminActivity" in snippets

    def test_exported_service_is_reported(self, apk_report):
        assert "MAN-EXPORTED-SERVICE" in rule_ids(apk_report)

    def test_boot_completed_receiver_is_not_reported(self, apk_report):
        """A receiver listening only for a system broadcast is not third-party reachable."""
        assert "MAN-EXPORTED-RECEIVER" not in rule_ids(apk_report)

    def test_unguarded_provider_is_reported(self, apk_report):
        finding = finding_for(apk_report, "MAN-EXPORTED-PROVIDER")
        assert "LeakyProvider" in " ".join(e.snippet for e in finding.evidence)

    def test_provider_with_a_read_permission_is_not_reported(self, apk_report):
        """GuardedProvider declares readPermission and must not be flagged."""
        finding = finding_for(apk_report, "MAN-EXPORTED-PROVIDER")
        assert "GuardedProvider" not in " ".join(e.snippet for e in finding.evidence)

    def test_sensitive_permissions_are_summarised(self, apk_report):
        finding = finding_for(apk_report, "MAN-SENSITIVE-PERMISSIONS")
        assert "android.permission.READ_SMS" in finding.metadata["permissions"]

    def test_low_min_sdk_is_reported(self, apk_report):
        assert "MAN-LOW-MIN-SDK" in rule_ids(apk_report)


class TestStorageAnalyzer:
    def test_world_readable_mode_is_detected_from_bytecode(self, apk_report):
        """MODE_WORLD_READABLE is an inlined int, recovered by constant tracking."""
        locations = " ".join(evidence_locations(apk_report, "STO-WORLD-READABLE"))
        assert "MainActivity.onCreate" in locations
        assert "StorageHelper.writeToken" in locations

    def test_world_writable_mode_is_critical(self, apk_report):
        assert finding_for(apk_report, "STO-WORLD-WRITABLE").severity.label == "Critical"

    def test_mode_private_is_not_reported(self, apk_report):
        """SecureHelper.store uses MODE_PRIVATE and must not appear."""
        for rule in ("STO-WORLD-READABLE", "STO-WORLD-WRITABLE"):
            assert not any("SecureHelper" in loc for loc in evidence_locations(apk_report, rule))

    def test_external_storage_use_is_reported(self, apk_report):
        locations = evidence_locations(apk_report, "STO-EXTERNAL-STORAGE")
        assert any("StorageHelper" in loc for loc in locations)

    def test_unencrypted_database_is_reported(self, apk_report):
        assert "STO-UNENCRYPTED-DB" in rule_ids(apk_report)


class TestNetworkAnalyzer:
    def test_cleartext_flag_is_reported(self, apk_report):
        assert finding_for(apk_report, "NET-CLEARTEXT-FLAG").owasp == "M5"

    def test_empty_trust_manager_is_critical(self, apk_report):
        finding = finding_for(apk_report, "NET-TRUSTMANAGER-ALLOW-ALL")
        assert finding.severity.label == "Critical"
        locations = " ".join(e.location for e in finding.evidence)
        assert "TrustEverything.checkServerTrusted" in locations

    def test_always_true_hostname_verifier_is_critical(self, apk_report):
        assert finding_for(apk_report, "NET-HOSTNAME-VERIFIER").severity.label == "Critical"

    def test_http_urls_are_collected_by_host(self, apk_report):
        hosts = finding_for(apk_report, "NET-HTTP-URL").metadata["hosts"]
        assert "api.insecure-demo.example.com" in hosts

    def test_schema_namespace_urls_are_not_reported_as_endpoints(self, apk_report):
        hosts = finding_for(apk_report, "NET-HTTP-URL").metadata["hosts"]
        assert "schemas.android.com" not in hosts
        assert "www.w3.org" not in hosts

    def test_https_endpoint_is_not_reported(self, apk_report):
        """SecureHelper.endpoint returns an https URL; it must not be flagged."""
        hosts = finding_for(apk_report, "NET-HTTP-URL").metadata["hosts"]
        assert "api.example.com" not in hosts

    def test_missing_pinning_is_low_severity(self, apk_report):
        finding = finding_for(apk_report, "NET-NO-PINNING")
        assert finding.severity.label == "Low"
        assert "not a defect" in finding.description


class TestCryptoAnalyzer:
    @pytest.mark.parametrize(
        "rule_id",
        ["CRY-WEAK-CIPHER-DES", "CRY-WEAK-CIPHER-RC4", "CRY-ECB-MODE",
         "CRY-WEAK-HASH-MD5", "CRY-WEAK-HASH-SHA1", "CRY-SEEDED-RANDOM",
         "CRY-HARDCODED-KEY"],
    )
    def test_expected_crypto_rules_fire(self, apk_report, rule_id: str):
        assert rule_id in rule_ids(apk_report)

    def test_weak_cipher_is_attributed_to_its_method(self, apk_report):
        locations = evidence_locations(apk_report, "CRY-WEAK-CIPHER-DES")
        assert any("CryptoHelper.encryptDes" in loc for loc in locations)

    def test_aes_gcm_is_not_reported(self, apk_report):
        """SecureHelper uses AES/GCM/NoPadding; it must not be flagged."""
        for rule in ("CRY-ECB-MODE", "CRY-DEFAULT-MODE"):
            assert not any("SecureHelper" in loc for loc in evidence_locations(apk_report, rule))

    def test_sha256_is_not_flagged_as_a_weak_hash(self, apk_report):
        weak = [f for f in apk_report.findings if f.rule_id.startswith("CRY-WEAK-HASH")]
        for finding in weak:
            assert "SHA-256" not in finding.title and "SHA256" not in finding.title


class TestWebViewAnalyzer:
    def test_javascript_interface_is_reported(self, apk_report):
        finding = finding_for(apk_report, "WEB-JS-INTERFACE")
        assert finding.owasp == "M4"
        assert finding.cwe == "CWE-749"

    def test_universal_file_access_is_critical(self, apk_report):
        finding = finding_for(apk_report, "WEB-UNIVERSAL-ACCESS-FROM-FILE-URLS")
        assert finding.severity.label == "Critical"

    def test_loadurl_from_intent_is_reported(self, apk_report):
        assert "WEB-LOADURL-FROM-INTENT" in rule_ids(apk_report)

    def test_custom_url_scheme_is_reported(self, apk_report):
        finding = finding_for(apk_report, "WEB-CUSTOM-URL-SCHEME")
        assert "vulnapp" in " ".join(e.snippet for e in finding.evidence)


class TestPrivacyAnalyzer:
    def test_sensitive_logging_is_reported(self, apk_report):
        finding = finding_for(apk_report, "PRI-SENSITIVE-LOGGING")
        assert finding.owasp == "M6"
        assert finding.cwe == "CWE-532"

    def test_logging_finding_is_attributed_to_methods(self, apk_report):
        locations = evidence_locations(apk_report, "PRI-SENSITIVE-LOGGING")
        assert any("MainActivity.onCreate" in loc for loc in locations)


class TestBinaryAnalyzer:
    @pytest.mark.parametrize(
        "rule_id", ["BIN-NO-OBFUSCATION", "BIN-NO-ROOT-DETECTION", "BIN-NO-ANTI-DEBUG"]
    )
    def test_absent_hardening_is_reported_at_low_severity(self, apk_report, rule_id):
        finding = finding_for(apk_report, rule_id)
        assert finding.severity.label in ("Low", "Info")
        assert finding.owasp == "M7"

    def test_absence_findings_say_they_are_not_defects(self, apk_report):
        for rule_id in ("BIN-NO-ROOT-DETECTION", "BIN-NO-ANTI-DEBUG"):
            description = finding_for(apk_report, rule_id).description
            assert "hardening" in description or "not a defect" in description


class TestOwaspMapping:
    def test_every_finding_maps_to_a_valid_category(self, apk_report):
        for finding in apk_report.findings:
            assert finding.owasp in {f"M{i}" for i in range(1, 11)}

    def test_findings_cover_most_of_the_top_ten(self, apk_report):
        covered = {f.owasp for f in apk_report.findings}
        assert len(covered) >= 8, f"only covered {sorted(covered)}"

    def test_every_finding_explains_itself(self, apk_report):
        for finding in apk_report.findings:
            assert len(finding.remediation) > 40, finding.rule_id
            assert len(finding.description) > 40, finding.rule_id

    def test_every_finding_has_evidence(self, apk_report):
        for finding in apk_report.findings:
            assert finding.evidence, f"{finding.rule_id} has no evidence"

    def test_rule_ids_are_stable_identifiers(self, apk_report):
        for finding in apk_report.findings:
            assert re.fullmatch(r"[A-Z0-9]+(-[A-Z0-9]+)*", finding.rule_id), finding.rule_id


class TestDecompilerAccuracy:
    """The parsers, checked against the sources the fixture was built from."""

    def test_manifest_attributes_match_the_source(self, apk_path: Path):
        with zipfile.ZipFile(apk_path) as archive:
            document = parse_axml(archive.read("AndroidManifest.xml"))
        application = document.find_all("application")[0]
        assert application.get_bool("android:debuggable") is True
        assert application.get_bool("android:allowBackup") is True
        assert application.get_bool("android:usesCleartextTraffic") is True

    def test_dex_classes_match_the_source_files(self, apk_path: Path):
        with zipfile.ZipFile(apk_path) as archive:
            dex = parse_dex(archive.read("classes.dex"))
        names = {c.name for c in dex.classes}
        for expected in (
            "com.masa.vulnerable.MainActivity",
            "com.masa.vulnerable.CryptoHelper",
            "com.masa.vulnerable.SecureHelper",
            "com.masa.vulnerable.NetworkHelper$TrustEverything",
        ):
            assert expected in names

    def test_constant_arguments_are_resolved(self, apk_path: Path):
        with zipfile.ZipFile(apk_path) as archive:
            dex = parse_dex(archive.read("classes.dex"))
        modes = {
            inv.site.class_name.rsplit(".", 1)[-1]: inv.arg(2)
            for inv in dex.invocations_by_name("getSharedPreferences")
        }
        assert modes["SecureHelper"] == 0  # MODE_PRIVATE
        assert modes["MainActivity"] in (1, 2)  # world readable/writable

    def test_trivial_method_bodies_are_classified(self, apk_path: Path):
        with zipfile.ZipFile(apk_path) as archive:
            dex = parse_dex(archive.read("classes.dex"))
        trust = {
            m.name: m
            for m in dex.methods_of("com.masa.vulnerable.NetworkHelper$TrustEverything")
        }
        assert trust["checkServerTrusted"].is_empty
        verify = {m.name: m for m in dex.methods_of("com.masa.vulnerable.NetworkHelper$1")}
        assert verify["verify"].returns_const == 1

    def test_resource_names_pair_with_their_values(self, apk_path: Path):
        with zipfile.ZipFile(apk_path) as archive:
            table = parse_arsc(archive.read("resources.arsc"))
        pairs = {entry.name: entry.value for entry in table.strings}
        assert pairs["app_name"] == "Vulnerable Demo"
        assert pairs["google_api_key"].startswith("AIza")
        assert pairs["backend_url"].startswith("http://")

    def test_signing_matches_apksigner_ground_truth(self, apk_path: Path):
        with zipfile.ZipFile(apk_path) as archive:
            names = archive.namelist()
        info = detect_signing(apk_path, names)
        schemes = " ".join(info.schemes)
        assert "v1" in schemes and "v2" in schemes and "v3" in schemes
        assert "v3.1" not in schemes  # apksigner reports v3.1 as absent
        certificate = info.certificates[0]
        assert certificate["signature_algorithms"] == ["sha256WithRSA"]
        assert certificate["weak_signature_algorithm"] is False
