"""Insecure communication (M5).

Cleartext traffic, TLS validation that has been switched off, and the absence of
certificate pinning. The TLS-disabled checks use method-body analysis rather than
name matching: a class implementing X509TrustManager is only a finding when its
`checkServerTrusted` actually does nothing.
"""

from __future__ import annotations

import re
from typing import Iterable, Iterator

from masa.analyzers.base import Analyzer, register
from masa.context import ScanContext
from masa.models import Confidence, Evidence, Finding, Platform, Severity

_HTTP_URL = re.compile(r"\bhttp://([A-Za-z0-9._\-]{2,255})(?::\d{1,5})?(?:/[^\s\"'<>]*)?")

# Hosts that are never real traffic: schema/namespace identifiers and loopback.
_IGNORED_HOSTS = frozenset(
    {
        "localhost", "127.0.0.1", "0.0.0.0", "::1",
        "schemas.android.com", "www.w3.org", "java.sun.com", "xml.org",
        "www.apache.org", "purl.org", "ns.adobe.com", "schema.org",
        "www.example.com", "example.com", "example.org", "goo.gl",
        "www.google.com", "maven.apache.org", "json-schema.org",
        "www.slf4j.org", "logging.apache.org", "www.w3.org",
    }
)

_PINNING_MARKERS = (
    "CertificatePinner",
    "certificatePinner",
    "okhttp3.CertificatePinner",
    "TrustKit",
    "pin-set",
    "network_security_config",
    "PinningTrustManager",
    "setCertificateChainValidator",
)


@register
class NetworkAnalyzer(Analyzer):
    name = "network"
    description = "Cleartext traffic, TLS validation bypasses and certificate pinning"
    platforms = (Platform.ANDROID, Platform.IOS)

    def analyze(self, ctx: ScanContext) -> Iterable[Finding]:
        if ctx.platform is Platform.ANDROID and ctx.android:
            yield from self._cleartext_flag(ctx)
            yield from self._network_security_config(ctx)
            yield from self._trust_manager(ctx)
            yield from self._hostname_verifier(ctx)
            yield from self._pinning(ctx)
        yield from self._http_urls(ctx)

    # -- Android manifest -----------------------------------------------------

    def _cleartext_flag(self, ctx: ScanContext) -> Iterator[Finding]:
        doc = ctx.android.manifest
        if doc is None:
            return
        for app in doc.find_all("application"):
            if app.get_bool("android:usesCleartextTraffic"):
                yield self.finding(
                    ctx,
                    rule_id="NET-CLEARTEXT-FLAG",
                    title="Cleartext HTTP traffic is explicitly permitted",
                    severity=Severity.HIGH,
                    owasp="M5",
                    cwe="CWE-319",
                    masvs="MASVS-NETWORK",
                    description=(
                        "`android:usesCleartextTraffic=\"true\"` is set, which "
                        "re-enables unencrypted HTTP for the whole app. Android "
                        "blocks cleartext by default from API 28 precisely because "
                        "anyone sharing the network — a coffee-shop access point, a "
                        "hostile ISP, someone with an ARP-spoofing tool — can read "
                        "and rewrite that traffic in transit."
                    ),
                    remediation=(
                        "Remove the attribute and serve every endpoint over HTTPS. "
                        "If one legacy host genuinely cannot be migrated yet, allow "
                        "just that domain in a network security config "
                        "(`<domain-config cleartextTrafficPermitted=\"true\">`) "
                        "rather than opening the whole app."
                    ),
                    evidence=[
                        self.evidence(
                            ctx, "AndroidManifest.xml",
                            'android:usesCleartextTraffic="true"',
                            line=app.line or None, redact=False,
                        )
                    ],
                    references=["https://cwe.mitre.org/data/definitions/319.html"],
                )

    def _network_security_config(self, ctx: ScanContext) -> Iterator[Finding]:
        doc = ctx.android.manifest
        if doc is None:
            return
        configured = any(
            app.get("android:networkSecurityConfig")
            for app in doc.find_all("application")
        )
        if configured:
            yield from self._inspect_nsc(ctx)
            return

        try:
            min_sdk = int(ctx.app.min_sdk) if ctx.app.min_sdk else None
        except ValueError:
            min_sdk = None
        if min_sdk is not None and min_sdk >= 28:
            return  # platform default already blocks cleartext and user CAs

        yield self.finding(
            ctx,
            rule_id="NET-NO-NSC",
            title="No network security configuration is declared",
            severity=Severity.MEDIUM,
            owasp="M5",
            cwe="CWE-295",
            masvs="MASVS-NETWORK",
            confidence=Confidence.MEDIUM,
            description=(
                "The app declares no `android:networkSecurityConfig`, and its "
                f"minSdkVersion ({ctx.app.min_sdk or 'unknown'}) is below 28. On "
                "those platform versions cleartext HTTP is allowed by default and — "
                "below API 24 — the app also trusts CAs the user has installed, "
                "which is exactly what makes traffic interception with a proxy "
                "certificate straightforward."
            ),
            remediation=(
                "Add a network security config that sets "
                "`cleartextTrafficPermitted=\"false\"` and restricts trust anchors "
                "to the system store, then reference it from <application>."
            ),
            evidence=[
                self.evidence(
                    ctx, "AndroidManifest.xml",
                    "no android:networkSecurityConfig attribute", redact=False,
                )
            ],
        )

    def _inspect_nsc(self, ctx: ScanContext) -> Iterator[Finding]:
        """Read the referenced config if it was extracted, and flag weak settings."""
        evidence: list[Evidence] = []
        for text_file in ctx.text_files():
            if "network" not in text_file.relative.lower():
                continue
            text = text_file.text
            if "network-security-config" not in text:
                continue
            if 'cleartextTrafficPermitted="true"' in text:
                evidence.append(
                    self.evidence(
                        ctx, text_file.relative,
                        'cleartextTrafficPermitted="true"', redact=False,
                    )
                )
            if "<certificates src=\"user\"" in text.replace(" ", ""):
                evidence.append(
                    self.evidence(
                        ctx, text_file.relative,
                        '<certificates src="user"> — trusts user-installed CAs',
                        redact=False,
                    )
                )
        if evidence:
            yield self.finding(
                ctx,
                rule_id="NET-WEAK-NSC",
                title="Network security config weakens TLS protections",
                severity=Severity.HIGH,
                owasp="M5",
                cwe="CWE-295",
                masvs="MASVS-NETWORK",
                description=(
                    "The network security configuration re-enables cleartext traffic "
                    "or adds the user certificate store as a trust anchor. Trusting "
                    "user-installed CAs means anyone who can get a certificate onto "
                    "the device — including any interception proxy — can read the "
                    "app's TLS traffic."
                ),
                remediation=(
                    "Set `cleartextTrafficPermitted=\"false\"` and limit "
                    "`<trust-anchors>` to `<certificates src=\"system\"/>`. Use a "
                    "debug-overrides block for the proxy trust developers need, since "
                    "that block is ignored in release builds."
                ),
                evidence=evidence,
            )

    # -- TLS validation -------------------------------------------------------

    def _trust_manager(self, ctx: ScanContext) -> Iterator[Finding]:
        evidence: list[Evidence] = []
        for entry in ctx.android.classes_implementing("javax.net.ssl.X509TrustManager"):
            for method in entry.methods:
                if method.name not in ("checkServerTrusted", "checkClientTrusted"):
                    continue
                # A validating implementation has real work in it; an empty body
                # (a bare return-void) accepts every certificate presented.
                if method.is_empty:
                    evidence.append(
                        self.evidence(
                            ctx,
                            f"{entry.name}.{method.name}()",
                            f"{method.name} has an empty body — accepts any certificate",
                            redact=False,
                        )
                    )
        if not evidence:
            return
        yield self.finding(
            ctx,
            rule_id="NET-TRUSTMANAGER-ALLOW-ALL",
            title="TrustManager accepts every certificate",
            severity=Severity.CRITICAL,
            owasp="M5",
            cwe="CWE-295",
            masvs="MASVS-NETWORK",
            description=(
                "A class implementing `X509TrustManager` has an empty "
                "`checkServerTrusted`. An empty implementation raises no exception, "
                "which is how the API says \"this certificate is valid\" — so the "
                "app accepts any certificate from any server, including a "
                "self-signed one an attacker generates. TLS still encrypts the "
                "connection, but to whoever intercepted it: the confidentiality and "
                "authentication guarantees are both gone, silently."
            ),
            remediation=(
                "Delete the custom TrustManager and use the platform default. If a "
                "private CA must be trusted, add it as a trust anchor in the network "
                "security config instead of writing validation code. Never ship the "
                "permissive version that was added to make a staging certificate work."
            ),
            evidence=evidence,
            references=[
                "https://cwe.mitre.org/data/definitions/295.html",
                "https://developer.android.com/privacy-and-security/security-ssl",
            ],
        )

    def _hostname_verifier(self, ctx: ScanContext) -> Iterator[Finding]:
        evidence: list[Evidence] = []
        for entry in ctx.android.classes_implementing("javax.net.ssl.HostnameVerifier"):
            for method in entry.methods:
                if method.name == "verify" and method.returns_const == 1:
                    evidence.append(
                        self.evidence(
                            ctx,
                            f"{entry.name}.verify()",
                            "verify() unconditionally returns true",
                            redact=False,
                        )
                    )
        for _, value in ctx.all_strings():
            if "ALLOW_ALL_HOSTNAME_VERIFIER" in value:
                evidence.append(
                    self.evidence(
                        ctx, "classes.dex (string pool)",
                        "ALLOW_ALL_HOSTNAME_VERIFIER", redact=False,
                    )
                )
                break
        if not evidence:
            return
        yield self.finding(
            ctx,
            rule_id="NET-HOSTNAME-VERIFIER",
            title="Hostname verification is disabled",
            severity=Severity.CRITICAL,
            owasp="M5",
            cwe="CWE-297",
            masvs="MASVS-NETWORK",
            description=(
                "A `HostnameVerifier` returns true for every hostname. Certificate "
                "chain validation may still pass, but nothing checks that the "
                "certificate was issued for the host actually being contacted — so "
                "any valid certificate for any domain is accepted, and an attacker "
                "needs only a legitimately-issued certificate for a domain they own."
            ),
            remediation=(
                "Remove the custom verifier and let the default implementation run. "
                "For a host whose certificate does not match its name, fix the "
                "certificate rather than the client."
            ),
            evidence=evidence,
            references=["https://cwe.mitre.org/data/definitions/297.html"],
        )

    def _pinning(self, ctx: ScanContext) -> Iterator[Finding]:
        if self._has_pinning(ctx):
            return
        yield self.finding(
            ctx,
            rule_id="NET-NO-PINNING",
            title="No certificate pinning was found",
            severity=Severity.LOW,
            owasp="M5",
            cwe="CWE-295",
            masvs="MASVS-NETWORK",
            confidence=Confidence.MEDIUM,
            description=(
                "No certificate or public-key pinning implementation was found "
                "(no OkHttp CertificatePinner, TrustKit, or `<pin-set>` in a network "
                "security config). Without pinning, the app trusts every CA in the "
                "system store, so a mis-issued or compromised CA certificate — or a "
                "CA an attacker can coerce — is enough to intercept traffic. "
                "Reported as an absent hardening measure, not a defect: pinning "
                "carries real operational risk if certificate rotation is not "
                "automated, and is not appropriate for every app."
            ),
            remediation=(
                "For an app handling authentication or financial data, pin to the "
                "public key (not the leaf certificate) of your own backends, include "
                "a backup pin, and make sure the rotation process is tested before "
                "shipping — a pin that expires bricks the app in the field."
            ),
            evidence=[
                self.evidence(
                    ctx, ctx.package.file_name,
                    "no pinning implementation found in the package", redact=False,
                )
            ],
        )

    @staticmethod
    def _has_pinning(ctx: ScanContext) -> bool:
        for _, value in ctx.all_strings():
            if any(marker in value for marker in _PINNING_MARKERS):
                return True
        for text_file in ctx.text_files():
            if "pin-set" in text_file.text or "CertificatePinner" in text_file.text:
                return True
        if ctx.android:
            for entry in ctx.android.all_classes():
                if "CertificatePinner" in entry.name or "TrustKit" in entry.name:
                    return True
        return False

    # -- shared ---------------------------------------------------------------

    def _http_urls(self, ctx: ScanContext) -> Iterator[Finding]:
        hosts: dict[str, Evidence] = {}
        for location, value in ctx.all_strings():
            for match in _HTTP_URL.finditer(value):
                host = match.group(1).lower()
                if host in _IGNORED_HOSTS or host.endswith(".local"):
                    continue
                if host not in hosts and len(hosts) < ctx.limits.max_evidence_per_finding:
                    hosts[host] = self.evidence(ctx, location, match.group(0))
        for text_file in ctx.text_files():
            if len(hosts) >= ctx.limits.max_evidence_per_finding:
                break
            for number, line in enumerate(text_file.lines(), start=1):
                for match in _HTTP_URL.finditer(line[: ctx.limits.max_line_bytes]):
                    host = match.group(1).lower()
                    if host in _IGNORED_HOSTS or host.endswith(".local"):
                        continue
                    if host not in hosts:
                        hosts[host] = self.evidence(
                            ctx, f"{text_file.relative}:{number}", match.group(0)
                        )

        if not hosts:
            return
        yield self.finding(
            ctx,
            rule_id="NET-HTTP-URL",
            title=f"Cleartext HTTP endpoints referenced ({len(hosts)} host(s))",
            severity=Severity.MEDIUM,
            owasp="M5",
            cwe="CWE-319",
            masvs="MASVS-NETWORK",
            confidence=Confidence.MEDIUM,
            description=(
                "The package contains `http://` URLs pointing at "
                + ", ".join(f"`{h}`" for h in sorted(hosts)[:8])
                + (" and others" if len(hosts) > 8 else "")
                + ". Traffic to these hosts is unencrypted and unauthenticated: it "
                "can be read and modified by anything on the network path. A URL in "
                "a string pool is not proof the app requests it at runtime — check "
                "the call sites — but each one is a candidate for interception."
            ),
            remediation=(
                "Move every endpoint to HTTPS. For URLs that are documentation "
                "links or namespace identifiers rather than requests, no change is "
                "needed beyond confirming that is what they are."
            ),
            evidence=list(hosts.values()),
            references=["https://cwe.mitre.org/data/definitions/319.html"],
            metadata={"hosts": sorted(hosts)[:50]},
        )
