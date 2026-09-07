"""iOS Info.plist and entitlement configuration (M8, with M5/M6 crossovers).

App Transport Security exceptions, URL scheme registration, missing permission
usage strings, file sharing, and entitlements that widen the app's reach.
"""

from __future__ import annotations

from typing import Iterable, Iterator

from masa.analyzers.base import Analyzer, register
from masa.context import ScanContext
from masa.models import Confidence, Evidence, Finding, Platform, Severity

_ATS_KEY = "NSAppTransportSecurity"

_PERMISSION_KEYS = {
    "NSCameraUsageDescription": "the camera",
    "NSMicrophoneUsageDescription": "the microphone",
    "NSLocationWhenInUseUsageDescription": "location while in use",
    "NSLocationAlwaysAndWhenInUseUsageDescription": "location at all times",
    "NSContactsUsageDescription": "the address book",
    "NSPhotoLibraryUsageDescription": "the photo library",
    "NSCalendarsUsageDescription": "calendars",
    "NSRemindersUsageDescription": "reminders",
    "NSHealthShareUsageDescription": "health data",
    "NSMotionUsageDescription": "motion and fitness data",
    "NSSpeechRecognitionUsageDescription": "speech recognition",
    "NSFaceIDUsageDescription": "Face ID",
    "NSBluetoothAlwaysUsageDescription": "Bluetooth",
    "NSUserTrackingUsageDescription": "cross-app tracking",
}

_RISKY_ENTITLEMENTS = {
    "get-task-allow": (
        "allows a debugger to attach to the app",
        Severity.HIGH,
        "`get-task-allow` is set. This entitlement lets any debugger attach to the "
        "running process and is only meant for development builds. In a shipped "
        "app it means memory, keys and control flow are open to inspection on a "
        "device the attacker controls.",
    ),
    "com.apple.security.get-task-allow": (
        "allows a debugger to attach to the app",
        Severity.HIGH,
        "`com.apple.security.get-task-allow` is set, allowing debuggers to attach.",
    ),
    "application-identifier": ("", Severity.INFO, ""),
}


@register
class IosConfigAnalyzer(Analyzer):
    name = "ios_config"
    description = "iOS Info.plist, App Transport Security and entitlement configuration"
    platforms = (Platform.IOS,)

    def analyze(self, ctx: ScanContext) -> Iterable[Finding]:
        if not ctx.ios:
            return
        info = ctx.ios.info_plist
        if not info:
            return
        yield from self._ats(ctx, info)
        yield from self._url_schemes(ctx, info)
        yield from self._permissions(ctx, info)
        yield from self._file_sharing(ctx, info)
        yield from self._min_os(ctx, info)
        yield from self._entitlements(ctx)

    # -- M5: App Transport Security -------------------------------------------

    def _ats(self, ctx: ScanContext, info: dict) -> Iterator[Finding]:
        ats = info.get(_ATS_KEY)
        if not isinstance(ats, dict):
            return  # ATS defaults apply in full; nothing to report

        if ats.get("NSAllowsArbitraryLoads") is True:
            exception_domains = ats.get("NSExceptionDomains")
            scoped = isinstance(exception_domains, dict) and bool(exception_domains)
            yield self.finding(
                ctx,
                rule_id="IOS-ATS-ARBITRARY-LOADS",
                title="App Transport Security is disabled globally",
                severity=Severity.MEDIUM if scoped else Severity.HIGH,
                owasp="M5",
                cwe="CWE-319",
                masvs="MASVS-NETWORK",
                description=(
                    "`NSAllowsArbitraryLoads` is true, which switches off ATS for "
                    "every connection the app makes: cleartext HTTP is permitted, "
                    "and TLS connections no longer have to meet the minimum version "
                    "and cipher requirements ATS enforces."
                    + (
                        " Exception domains are also declared, so on iOS 10+ the "
                        "global flag is ignored for those specific domains — but it "
                        "still applies to everything else."
                        if scoped
                        else " No exception domains narrow it."
                    )
                ),
                remediation=(
                    "Remove `NSAllowsArbitraryLoads` and serve every endpoint over "
                    "TLS 1.2+. Where one legacy host cannot be fixed yet, add just "
                    "that host under `NSExceptionDomains` — App Review requires a "
                    "justification for the global flag in any case."
                ),
                evidence=[
                    self.evidence(
                        ctx, "Info.plist", "NSAllowsArbitraryLoads = true", redact=False
                    )
                ],
                references=["https://cwe.mitre.org/data/definitions/319.html"],
            )

        for flag, rule_suffix, label in (
            ("NSAllowsArbitraryLoadsInWebContent", "WEB-CONTENT", "web content"),
            ("NSAllowsArbitraryLoadsForMedia", "MEDIA", "media loaded via AV Foundation"),
            ("NSAllowsLocalNetworking", "LOCAL-NETWORK", "local network connections"),
        ):
            if ats.get(flag) is True:
                yield self.finding(
                    ctx,
                    rule_id=f"IOS-ATS-{rule_suffix}",
                    title=f"App Transport Security exempts {label}",
                    severity=Severity.LOW if flag == "NSAllowsLocalNetworking" else Severity.MEDIUM,
                    owasp="M5",
                    cwe="CWE-319",
                    masvs="MASVS-NETWORK",
                    confidence=Confidence.HIGH,
                    description=(
                        f"`{flag}` is true, so ATS does not apply to {label}. "
                        "Traffic in that category may be cleartext or use TLS "
                        "configurations ATS would otherwise reject."
                    ),
                    remediation=(
                        f"Remove `{flag}` unless a shipped feature depends on it, and "
                        "load web content over HTTPS."
                    ),
                    evidence=[
                        self.evidence(ctx, "Info.plist", f"{flag} = true", redact=False)
                    ],
                )

        exceptions = ats.get("NSExceptionDomains")
        if isinstance(exceptions, dict):
            evidence: list[Evidence] = []
            for domain, settings in exceptions.items():
                if not isinstance(settings, dict):
                    continue
                weak = [
                    key
                    for key in (
                        "NSExceptionAllowsInsecureHTTPLoads",
                        "NSThirdPartyExceptionAllowsInsecureHTTPLoads",
                        "NSExceptionRequiresForwardSecrecy",
                    )
                    if settings.get(key) is (False if "ForwardSecrecy" in key else True)
                ]
                minimum = settings.get("NSExceptionMinimumTLSVersion")
                if isinstance(minimum, str) and minimum in ("TLSv1.0", "TLSv1.1"):
                    weak.append(f"NSExceptionMinimumTLSVersion={minimum}")
                if weak:
                    evidence.append(
                        self.evidence(
                            ctx, "Info.plist",
                            f"{domain}: {', '.join(weak)}", redact=False,
                        )
                    )
            if evidence:
                yield self.finding(
                    ctx,
                    rule_id="IOS-ATS-EXCEPTION-DOMAINS",
                    title=f"ATS exceptions weaken TLS for {len(evidence)} domain(s)",
                    severity=Severity.MEDIUM,
                    owasp="M5",
                    cwe="CWE-319",
                    masvs="MASVS-NETWORK",
                    description=(
                        "Specific domains are exempted from App Transport Security: "
                        "they permit cleartext HTTP, drop the forward-secrecy "
                        "requirement, or allow a TLS version below 1.2. Traffic to "
                        "those hosts is weaker than the rest of the app's."
                    ),
                    remediation=(
                        "Fix the server configuration and remove the exception. "
                        "TLS 1.0 and 1.1 are deprecated (RFC 8996) and connections "
                        "without forward secrecy are retrospectively decryptable if "
                        "the server key is ever compromised."
                    ),
                    evidence=evidence,
                )

    # -- M4: URL schemes ------------------------------------------------------

    def _url_schemes(self, ctx: ScanContext, info: dict) -> Iterator[Finding]:
        schemes: list[str] = []
        for entry in info.get("CFBundleURLTypes", []) or []:
            if isinstance(entry, dict):
                schemes.extend(
                    s for s in entry.get("CFBundleURLSchemes", []) or [] if isinstance(s, str)
                )
        if not schemes:
            return
        yield self.finding(
            ctx,
            rule_id="IOS-CUSTOM-URL-SCHEME",
            title=f"Application registers {len(schemes)} custom URL scheme(s)",
            severity=Severity.MEDIUM,
            owasp="M4",
            cwe="CWE-939",
            masvs="MASVS-PLATFORM",
            confidence=Confidence.MEDIUM,
            description=(
                "The app registers the custom URL scheme(s) "
                + ", ".join(f"`{s}://`" for s in sorted(set(schemes))[:10])
                + ". Any app or web page can open these URLs and control the "
                "parameters the app receives. iOS does not verify scheme ownership: "
                "another app can register the same scheme, and if it is installed "
                "second the system's choice of handler is undefined — which is the "
                "basis of URL-scheme hijacking against OAuth callbacks."
            ),
            remediation=(
                "Validate and canonicalise every parameter arriving through "
                "`application(_:open:options:)`, and check the `sourceApplication` "
                "where it matters. For authentication callbacks use Universal Links "
                "bound to a domain you control, or `ASWebAuthenticationSession`, "
                "rather than a custom scheme."
            ),
            evidence=[
                self.evidence(ctx, "Info.plist", f"CFBundleURLSchemes: {s}", redact=False)
                for s in sorted(set(schemes))[:20]
            ],
            references=["https://cwe.mitre.org/data/definitions/939.html"],
        )

    # -- M6: permission strings ----------------------------------------------

    def _permissions(self, ctx: ScanContext, info: dict) -> Iterator[Finding]:
        declared = {key: info[key] for key in _PERMISSION_KEYS if key in info}
        if not declared:
            return

        vague = [
            key
            for key, value in declared.items()
            if not isinstance(value, str) or len(value.strip()) < 15
        ]
        yield self.finding(
            ctx,
            rule_id="IOS-PERMISSION-USAGE",
            title=f"Application requests {len(declared)} sensitive permission(s)",
            severity=Severity.MEDIUM if vague else Severity.LOW,
            owasp="M6",
            cwe="CWE-359",
            masvs="MASVS-PRIVACY",
            confidence=Confidence.HIGH,
            description=(
                "The app declares usage descriptions for: "
                + ", ".join(
                    f"{_PERMISSION_KEYS[key]} (`{key}`)" for key in sorted(declared)
                )
                + ". "
                + (
                    f"{len(vague)} of these have a missing or very short "
                    "justification string, which is what the user is shown at the "
                    "permission prompt — a vague string means the user cannot make "
                    "an informed decision, and App Review rejects it."
                    if vague
                    else "Each has a usage string, which is what the user sees at "
                    "the prompt."
                )
            ),
            remediation=(
                "Request only what a shipped feature needs, and write a usage string "
                "that names the specific feature and why it needs the data."
            ),
            evidence=[
                self.evidence(
                    ctx, "Info.plist",
                    f"{key}: {str(declared[key])[:80] or '(empty)'}", redact=False,
                )
                for key in sorted(declared)
            ],
            metadata={"vague_descriptions": vague},
        )

    # -- M8: bundle configuration ---------------------------------------------

    def _file_sharing(self, ctx: ScanContext, info: dict) -> Iterator[Finding]:
        sharing = info.get("UIFileSharingEnabled") is True
        docs_in_place = info.get("LSSupportsOpeningDocumentsInPlace") is True
        if not sharing:
            return
        yield self.finding(
            ctx,
            rule_id="IOS-FILE-SHARING",
            title="Application exposes its Documents directory over file sharing",
            severity=Severity.MEDIUM,
            owasp="M8",
            cwe="CWE-552",
            masvs="MASVS-STORAGE",
            description=(
                "`UIFileSharingEnabled` is true"
                + (" together with `LSSupportsOpeningDocumentsInPlace`" if docs_in_place else "")
                + ", so the app's Documents directory is visible in the Files app "
                "and over USB via iTunes/Finder. Anything the app writes there is "
                "readable, and replaceable, by anyone with access to the unlocked "
                "device — including files the app later reads back and trusts."
            ),
            remediation=(
                "Disable file sharing unless the app's purpose is document exchange. "
                "Keep anything sensitive in Library/ or Application Support/ rather "
                "than Documents/, and re-validate any file read back from a "
                "user-writable location."
            ),
            evidence=[
                self.evidence(ctx, "Info.plist", "UIFileSharingEnabled = true", redact=False)
            ],
            references=["https://cwe.mitre.org/data/definitions/552.html"],
        )

    def _min_os(self, ctx: ScanContext, info: dict) -> Iterator[Finding]:
        minimum = info.get("MinimumOSVersion")
        if not isinstance(minimum, str):
            return
        try:
            major = int(minimum.split(".")[0])
        except (ValueError, IndexError):
            return
        if major >= 13:
            return
        yield self.finding(
            ctx,
            rule_id="IOS-LOW-MIN-OS",
            title=f"Minimum iOS version {minimum} is well behind current releases",
            severity=Severity.LOW,
            owasp="M8",
            cwe="CWE-1104",
            masvs="MASVS-PLATFORM",
            description=(
                f"`MinimumOSVersion` is {minimum}. Devices on that release no longer "
                "receive security updates, and the app cannot rely on platform "
                "mitigations introduced since — so it must carry those protections "
                "itself."
            ),
            remediation=(
                "Raise the deployment target if the install base allows. While "
                "supporting older releases, do not assume newer ATS, Keychain or "
                "privacy defaults are in effect."
            ),
            evidence=[
                self.evidence(ctx, "Info.plist", f"MinimumOSVersion = {minimum}", redact=False)
            ],
        )

    def _entitlements(self, ctx: ScanContext) -> Iterator[Finding]:
        entitlements = ctx.ios.entitlements
        if not entitlements:
            return
        for key, (_label, severity, explanation) in _RISKY_ENTITLEMENTS.items():
            if entitlements.get(key) is not True:
                continue
            if severity is Severity.INFO:
                continue
            yield self.finding(
                ctx,
                rule_id=f"IOS-ENTITLEMENT-{key.rsplit('.', 1)[-1].upper()}",
                title="Debug entitlement present in the shipped build",
                severity=severity,
                owasp="M8",
                cwe="CWE-489",
                masvs="MASVS-RESILIENCE",
                description=explanation,
                remediation=(
                    "Build for distribution with a provisioning profile that does not "
                    "grant `get-task-allow`. App Store builds strip it automatically; "
                    "its presence means this is an ad-hoc, enterprise or development "
                    "build."
                ),
                evidence=[
                    self.evidence(
                        ctx, "embedded.mobileprovision", f"{key} = true", redact=False
                    )
                ],
            )
