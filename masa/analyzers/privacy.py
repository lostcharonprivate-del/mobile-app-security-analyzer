"""Inadequate privacy controls (M6).

Personal data and credentials reaching the system log, and third-party trackers
bundled into the app.
"""

from __future__ import annotations

import re
from typing import Iterable, Iterator

from masa.analyzers.base import Analyzer, register
from masa.context import ScanContext
from masa.models import Confidence, Evidence, Finding, Platform, Severity

_LOG_METHODS = ("d", "v", "i", "w", "e", "wtf", "println")

# Words that, appearing in a string that is logged, indicate the log line carries
# a credential or personal data rather than a status message.
_SENSITIVE_WORDS = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|apikey|credential|"
    r"auth|session|jwt|bearer|otp|pin|ssn|imei|iccid|latitude|longitude|"
    r"email|phone[_-]?number|credit[_-]?card|cvv|account[_-]?number)\b"
)

_TRACKERS = {
    "com.google.android.gms.analytics": "Google Analytics",
    "com.google.firebase.analytics": "Firebase Analytics",
    "com.facebook.appevents": "Meta (Facebook) App Events",
    "com.facebook.ads": "Meta Audience Network",
    "com.appsflyer": "AppsFlyer",
    "com.adjust.sdk": "Adjust",
    "io.branch": "Branch",
    "com.mixpanel": "Mixpanel",
    "com.amplitude": "Amplitude",
    "com.segment.analytics": "Segment",
    "com.flurry": "Flurry",
    "com.onesignal": "OneSignal",
    "com.crashlytics": "Crashlytics",
    "com.umeng": "Umeng",
    "com.mopub": "MoPub",
    "com.unity3d.ads": "Unity Ads",
    "com.applovin": "AppLovin",
    "com.chartboost": "Chartboost",
    "com.inmobi": "InMobi",
    "com.tapjoy": "Tapjoy",
}

_DEVICE_ID_METHODS = {
    "getDeviceId": "IMEI / MEID",
    "getImei": "IMEI",
    "getSubscriberId": "IMSI",
    "getSimSerialNumber": "SIM serial number",
    "getLine1Number": "the device's phone number",
    "getMacAddress": "the Wi-Fi MAC address",
    "getAndroidId": "the Android ID",
}


@register
class PrivacyAnalyzer(Analyzer):
    name = "privacy"
    description = "Sensitive data in logs, bundled trackers and device identifiers"
    platforms = (Platform.ANDROID, Platform.IOS)

    def analyze(self, ctx: ScanContext) -> Iterable[Finding]:
        if ctx.platform is Platform.ANDROID and ctx.android:
            yield from self._sensitive_logging(ctx)
            yield from self._device_identifiers(ctx)
        yield from self._trackers(ctx)
        if ctx.platform is Platform.IOS:
            yield from self._ios_logging(ctx)

    def _sensitive_logging(self, ctx: ScanContext) -> Iterator[Finding]:
        """Find log calls whose method also loads a credential-shaped string."""
        log_locations: set[str] = set()
        for name in _LOG_METHODS:
            for site in ctx.android.sites_by_name(name, receivers=("Log",)):
                log_locations.add(site.location)
        if not log_locations:
            return

        evidence: list[Evidence] = []
        matched_locations: set[str] = set()
        for location, value in ctx.all_strings():
            if location not in log_locations:
                continue
            if not _SENSITIVE_WORDS.search(value):
                continue
            matched_locations.add(location)
            if len(evidence) < ctx.limits.max_evidence_per_finding:
                evidence.append(self.evidence(ctx, location, value))

        if not evidence:
            # Logging exists but nothing sensitive-looking is logged: report the
            # presence of debug logging only, at Info.
            yield self.finding(
                ctx,
                rule_id="PRI-DEBUG-LOGGING",
                title="Debug logging is present in the shipped build",
                severity=Severity.INFO,
                owasp="M6",
                cwe="CWE-532",
                masvs="MASVS-PRIVACY",
                confidence=Confidence.MEDIUM,
                description=(
                    f"`android.util.Log` is called from {len(log_locations)} "
                    "location(s). Nothing obviously sensitive was found in the "
                    "logged strings, so this is informational — but log statements "
                    "left in a release build tend to accumulate, and on Android 4.1+ "
                    "an app can only read its own logs, which limits though does not "
                    "eliminate the exposure."
                ),
                remediation=(
                    "Strip verbose and debug logging from release builds — a ProGuard "
                    "`assumenosideeffects` rule for `Log.d`/`Log.v` removes the calls "
                    "and their string construction entirely."
                ),
                evidence=[
                    self.evidence(ctx, location, "Log call", redact=False)
                    for location in sorted(log_locations)[:10]
                ],
            )
            return

        yield self.finding(
            ctx,
            rule_id="PRI-SENSITIVE-LOGGING",
            title="Credentials or personal data are written to the system log",
            severity=Severity.HIGH,
            owasp="M6",
            cwe="CWE-532",
            masvs="MASVS-PRIVACY",
            confidence=Confidence.MEDIUM,
            description=(
                f"{len(matched_locations)} method(s) call `android.util.Log` and, in "
                "the same method, load strings referring to passwords, tokens or "
                "personal identifiers. Log output is written to the device log "
                "buffer, is captured by bug reports and crash reporters, and is "
                "readable by anyone with ADB access or a debuggable build. A "
                "credential that reaches the log has left the app's control."
            ),
            remediation=(
                "Remove these log statements. Where the log line is genuinely useful, "
                "log a non-identifying reference instead of the value — an event name "
                "or a hashed identifier — and strip debug logging from release builds "
                "with a ProGuard `assumenosideeffects` rule."
            ),
            evidence=evidence,
            references=["https://cwe.mitre.org/data/definitions/532.html"],
            metadata={"log_call_sites": len(log_locations)},
        )

    def _ios_logging(self, ctx: ScanContext) -> Iterator[Finding]:
        strings = [v for _, v in ctx.all_strings()]
        if not any("NSLog" in v or "os_log" in v for v in strings):
            return
        sensitive = [v for v in strings if _SENSITIVE_WORDS.search(v) and "%" in v]
        if not sensitive:
            return
        yield self.finding(
            ctx,
            rule_id="PRI-IOS-NSLOG",
            title="Format strings suggest sensitive data is logged",
            severity=Severity.MEDIUM,
            owasp="M6",
            cwe="CWE-532",
            masvs="MASVS-PRIVACY",
            confidence=Confidence.LOW,
            description=(
                "The binary references NSLog/os_log and contains format strings that "
                "name credentials or personal data. NSLog output goes to the unified "
                "system log, where it persists and is visible to anyone with the "
                "device connected to a Mac."
            ),
            remediation=(
                "Use `os_log` with the default privacy level, which redacts dynamic "
                "values automatically, and never mark a value `%{public}@` unless it "
                "is genuinely safe to disclose."
            ),
            evidence=[
                self.evidence(ctx, "main binary (strings)", value)
                for value in sensitive[:10]
            ],
        )

    def _device_identifiers(self, ctx: ScanContext) -> Iterator[Finding]:
        evidence: list[Evidence] = []
        found: set[str] = set()
        for method, label in _DEVICE_ID_METHODS.items():
            sites = ctx.android.sites_by_name(method)
            if not sites:
                continue
            found.add(label)
            evidence.extend(
                self.evidence(ctx, site.location, f"{method}() — reads {label}", redact=False)
                for site in sites[:5]
            )
        if not evidence:
            return
        yield self.finding(
            ctx,
            rule_id="PRI-DEVICE-IDENTIFIERS",
            title="Application reads persistent device identifiers",
            severity=Severity.MEDIUM,
            owasp="M6",
            cwe="CWE-359",
            masvs="MASVS-PRIVACY",
            confidence=Confidence.MEDIUM,
            description=(
                "The app reads " + ", ".join(sorted(found)) + ". These identifiers "
                "cannot be reset by the user, so they allow tracking that persists "
                "across uninstalls and app boundaries. Google Play policy restricts "
                "their use, and since Android 10 most are unavailable to non-system "
                "apps — code that still reads them either fails silently or targets "
                "older devices."
            ),
            remediation=(
                "Use a resettable advertising ID for attribution, or an app-scoped "
                "identifier you generate and store yourself, so uninstalling the app "
                "actually clears it."
            ),
            evidence=evidence,
            references=["https://cwe.mitre.org/data/definitions/359.html"],
        )

    def _trackers(self, ctx: ScanContext) -> Iterator[Finding]:
        found: dict[str, str] = {}
        classes: list[str] = []
        if ctx.android:
            classes = [entry.name for entry in ctx.android.all_classes()]
        haystack = classes + [v for _, v in ctx.all_strings()][:50_000]

        for package, label in _TRACKERS.items():
            for value in haystack:
                if package in value:
                    found[label] = package
                    break
        if not found:
            return
        yield self.finding(
            ctx,
            rule_id="PRI-TRACKERS",
            title=f"{len(found)} third-party analytics or advertising SDK(s) bundled",
            severity=Severity.LOW if len(found) <= 2 else Severity.MEDIUM,
            owasp="M6",
            cwe="CWE-359",
            masvs="MASVS-PRIVACY",
            confidence=Confidence.MEDIUM,
            description=(
                "The package embeds: "
                + ", ".join(f"{label} (`{pkg}`)" for label, pkg in sorted(found.items()))
                + ". Each of these sends data to a third party from inside the app's "
                "process, with the app's permissions. This is reported for disclosure "
                "and consent review, not as a defect — but the data each SDK collects "
                "has to appear in the privacy policy and in the store data-safety "
                "declaration, and under GDPR/CCPA it generally requires consent "
                "before the SDK initialises."
            ),
            remediation=(
                "Confirm each SDK is disclosed in the privacy policy and the store "
                "listing, that it initialises only after consent where consent is "
                "required, and that no SDK receives more than it needs. Remove any "
                "that arrived as a transitive dependency and is not actually used."
            ),
            evidence=[
                self.evidence(ctx, "bundled classes", f"{label}: {pkg}", redact=False)
                for label, pkg in sorted(found.items())
            ],
            metadata={"trackers": sorted(found)},
        )
