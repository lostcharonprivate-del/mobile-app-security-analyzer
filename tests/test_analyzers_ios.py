"""iOS detection correctness against the compiled vulnerable fixture.

The fixture's binary is a genuine arm64 iOS Mach-O built by clang against the
iPhoneOS SDK, so the Mach-O reader is exercised on real linker output rather than
on a hand-assembled header.
"""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from masa.decompile.macho import parse_macho


def rule_ids(report) -> set[str]:
    return {finding.rule_id for finding in report.findings}


def finding_for(report, rule_id: str):
    matches = [f for f in report.findings if f.rule_id == rule_id]
    assert matches, f"{rule_id} did not fire"
    return matches[0]


class TestBundleMetadata:
    def test_bundle_metadata_is_recovered(self, ipa_report):
        app = ipa_report.app
        assert app.package_name == "com.masa.vulnerable-ios"
        assert app.version_name == "2.4.1"
        assert app.version_code == "241"
        assert app.min_os_version == "11.0"

    def test_url_schemes_are_listed(self, ipa_report):
        assert set(ipa_report.app.extra["url_schemes"]) == {"vulndemo", "vulndemo-auth"}

    def test_usage_description_keys_are_listed_as_permissions(self, ipa_report):
        assert "NSCameraUsageDescription" in ipa_report.app.permissions

    def test_frameworks_are_enumerated(self, ipa_report):
        assert "DemoAnalytics.framework" in ipa_report.app.extra["frameworks"]

    def test_macho_facts_are_reported(self, ipa_report):
        macho = ipa_report.app.extra["macho"]
        assert macho["cpu_type"] == "arm64"
        assert macho["pie"] is True
        assert macho["encrypted"] is False

    def test_scan_reports_no_internal_errors(self, ipa_report):
        assert ipa_report.errors == []


class TestAppTransportSecurity:
    def test_global_arbitrary_loads_is_reported(self, ipa_report):
        finding = finding_for(ipa_report, "IOS-ATS-ARBITRARY-LOADS")
        assert finding.owasp == "M5"
        assert finding.cwe == "CWE-319"

    def test_web_content_exemption_is_reported(self, ipa_report):
        assert "IOS-ATS-WEB-CONTENT" in rule_ids(ipa_report)

    def test_weak_exception_domains_are_reported(self, ipa_report):
        finding = finding_for(ipa_report, "IOS-ATS-EXCEPTION-DOMAINS")
        snippets = " ".join(e.snippet for e in finding.evidence)
        assert "insecure-ios-demo.example.com" in snippets
        assert "TLSv1.0" in snippets

    def test_rule_ids_do_not_leak_plist_key_spelling(self, ipa_report):
        """Rule IDs are stable identifiers, not raw camelCase plist keys."""
        import re

        for finding in ipa_report.findings:
            assert re.fullmatch(r"[A-Z0-9]+(-[A-Z0-9]+)*", finding.rule_id), finding.rule_id


class TestBundleConfiguration:
    def test_file_sharing_is_reported(self, ipa_report):
        assert finding_for(ipa_report, "IOS-FILE-SHARING").owasp == "M8"

    def test_custom_url_schemes_are_reported(self, ipa_report):
        finding = finding_for(ipa_report, "IOS-CUSTOM-URL-SCHEME")
        assert finding.owasp == "M4"
        assert "vulndemo" in " ".join(e.snippet for e in finding.evidence)

    def test_low_minimum_os_is_reported(self, ipa_report):
        assert "IOS-LOW-MIN-OS" in rule_ids(ipa_report)

    def test_vague_permission_string_raises_the_severity(self, ipa_report):
        finding = finding_for(ipa_report, "IOS-PERMISSION-USAGE")
        # NSCameraUsageDescription is "We need it." and NSContactsUsageDescription is empty.
        assert "NSCameraUsageDescription" in finding.metadata["vague_descriptions"]
        assert finding.severity.label == "Medium"

    def test_debug_entitlement_is_reported(self, ipa_report):
        """get-task-allow is carved out of the CMS-wrapped provisioning profile."""
        finding = finding_for(ipa_report, "IOS-ENTITLEMENT-GET-TASK-ALLOW")
        assert finding.severity.label == "High"
        assert finding.owasp == "M8"


class TestIosStorageAndSecrets:
    def test_weak_keychain_accessibility_is_reported(self, ipa_report):
        finding = finding_for(ipa_report, "STO-IOS-KEYCHAIN-ACCESSIBLE")
        assert finding.severity.label == "High"
        assert "kSecAttrAccessibleAlways" in " ".join(e.snippet for e in finding.evidence)

    def test_userdefaults_with_credential_keys_is_reported(self, ipa_report):
        assert "STO-IOS-USERDEFAULTS" in rule_ids(ipa_report)

    @pytest.mark.parametrize(
        "rule_id", ["SEC-AWS-AKID", "SEC-STRIPE", "SEC-GITHUB-PAT", "SEC-GCP-APIKEY", "SEC-JWT"]
    )
    def test_secrets_in_the_binary_are_found(self, ipa_report, rule_id: str):
        assert rule_id in rule_ids(ipa_report)

    def test_credential_named_plist_keys_are_reported(self, ipa_report):
        named = [f for f in ipa_report.findings if f.rule_id == "SEC-NAMED-RESOURCE"]
        titles = " ".join(f.title for f in named)
        assert "db_password" in titles or "analytics_client_secret" in titles

    def test_nslog_of_sensitive_data_is_reported(self, ipa_report):
        assert finding_for(ipa_report, "PRI-IOS-NSLOG").owasp == "M6"

    def test_http_endpoints_in_the_binary_are_reported(self, ipa_report):
        hosts = finding_for(ipa_report, "NET-HTTP-URL").metadata["hosts"]
        assert any("insecure-ios-demo.example.com" in host for host in hosts)


class TestIosBinaryProtections:
    def test_missing_jailbreak_detection_is_reported_at_low_severity(self, ipa_report):
        finding = finding_for(ipa_report, "BIN-NO-JAILBREAK-DETECTION")
        assert finding.severity.label == "Low"
        assert "not a defect" in finding.description

    def test_unencrypted_binary_is_informational(self, ipa_report):
        finding = finding_for(ipa_report, "BIN-IOS-NOT-ENCRYPTED")
        assert finding.severity.label == "Info"
        assert "development" in finding.description

    def test_pie_binary_is_not_flagged(self, ipa_report):
        """The fixture is built PIE, so the no-PIE rule must stay quiet."""
        assert "BIN-IOS-NO-PIE" not in rule_ids(ipa_report)


class TestAndroidRulesDoNotRunOnIos(object):
    def test_manifest_analyzer_is_skipped(self, ipa_report):
        assert not any(f.analyzer == "manifest" for f in ipa_report.findings)

    def test_no_android_only_rule_fires(self, ipa_report):
        android_only = {"MAN-DEBUGGABLE", "NET-CLEARTEXT-FLAG", "WEB-JS-INTERFACE",
                        "STO-WORLD-READABLE", "BIN-NO-ROOT-DETECTION"}
        assert not (rule_ids(ipa_report) & android_only)


class TestMachOAccuracy:
    """Checked against what clang and the linker actually produced."""

    @staticmethod
    @pytest.fixture(scope="class")
    def macho(ipa_path: Path) -> bytes:
        with zipfile.ZipFile(ipa_path) as archive:
            name = next(n for n in archive.namelist() if n.endswith(".app/VulnerableDemo"))
            return archive.read(name)

    def test_header_fields_match_the_build(self, macho: bytes):
        info = parse_macho(macho)
        assert info.is_64bit is True
        assert info.cpu_type == "arm64"
        assert info.has_pie is True
        assert info.crypt_id == 0

    def test_linked_libraries_are_recovered(self, macho: bytes):
        info = parse_macho(macho)
        joined = " ".join(info.dylibs)
        assert "Foundation" in joined
        assert "libSystem" in joined

    def test_objc_class_names_are_recovered_without_class_dump(self, macho: bytes):
        """The __objc_classname section gives what class-dump would, with no tool."""
        info = parse_macho(macho)
        assert "DemoCredentialStore" in info.objc_classes
        assert "DemoNetworkClient" in info.objc_classes
        assert "DemoCryptoHelper" in info.objc_classes

    def test_objc_selector_names_are_recovered(self, macho: bytes):
        info = parse_macho(macho)
        assert any("persistToken" in selector for selector in info.objc_methods)
        assert any("weakHashOfPassword" in selector for selector in info.objc_methods)
