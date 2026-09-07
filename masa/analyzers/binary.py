"""Insufficient binary protections (M7).

Whether the shipped binary resists inspection and tampering at all: obfuscation,
root/jailbreak detection, anti-debugging, and native hardening flags.

Absence is reported as a finding, deliberately at low severity. These are
defence-in-depth measures, not vulnerabilities — an app with none of them is not
broken, it is just cheap to reverse engineer and repackage. That distinction is
stated in every finding this analyzer produces.
"""

from __future__ import annotations

import re
from typing import Iterable, Iterator

from masa.analyzers.base import Analyzer, register
from masa.context import ScanContext
from masa.models import Confidence, Evidence, Finding, Platform, Severity

_ROOT_MARKERS = (
    "/system/app/Superuser.apk", "/sbin/su", "/system/bin/su", "/system/xbin/su",
    "com.noshufou.android.su", "com.thirdparty.superuser", "eu.chainfire.supersu",
    "com.topjohnwu.magisk", "de.robv.android.xposed", "RootBeer", "isDeviceRooted",
    "test-keys", "/system/bin/failsafe/su", "which su",
)

_JAILBREAK_MARKERS = (
    "/Applications/Cydia.app", "/bin/bash", "/usr/sbin/sshd", "/etc/apt",
    "cydia://", "/private/var/lib/apt", "MobileSubstrate", "frida", "Sileo",
)

_ANTI_DEBUG_MARKERS = (
    "isDebuggerConnected", "android.os.Debug", "ptrace", "TracerPid",
    "sysctl", "PT_DENY_ATTACH", "IsDebuggerPresent",
)

_EMULATOR_MARKERS = ("goldfish", "ranchu", "generic_x86", "Genymotion", "vbox86")

# ProGuard/R8 renames classes and members to single letters; a package full of
# them is the signature of an obfuscated build.
_SHORT_NAME = re.compile(r"(^|\.)[a-z]{1,2}$")


@register
class BinaryProtectionAnalyzer(Analyzer):
    name = "binary"
    description = "Obfuscation, root/jailbreak detection, anti-debugging and binary hardening"
    platforms = (Platform.ANDROID, Platform.IOS)

    def analyze(self, ctx: ScanContext) -> Iterable[Finding]:
        if ctx.platform is Platform.ANDROID and ctx.android:
            yield from self._obfuscation(ctx)
            yield from self._root_detection(ctx)
            yield from self._debug_symbols(ctx)
        if ctx.platform is Platform.IOS and ctx.ios:
            yield from self._ios_protections(ctx)
        yield from self._anti_debugging(ctx)

    def _obfuscation(self, ctx: ScanContext) -> Iterator[Finding]:
        classes = [entry.name for entry in ctx.android.all_classes()]
        app_classes = [
            name
            for name in classes
            if name and not name.startswith(("android.", "androidx.", "kotlin.", "java."))
        ]
        if not app_classes:
            return

        obfuscated = sum(1 for name in app_classes if _SHORT_NAME.search(name))
        ratio = obfuscated / len(app_classes)
        # Source-file names survive unless the build strips them; their presence
        # is a second, independent signal that no shrinker ran.
        with_source = sum(
            1
            for entry in ctx.android.all_classes()
            if entry.source_file and entry.source_file.endswith((".java", ".kt"))
        )

        if ratio >= 0.3:
            return  # substantially obfuscated

        yield self.finding(
            ctx,
            rule_id="BIN-NO-OBFUSCATION",
            title="Application code is not obfuscated",
            severity=Severity.LOW,
            owasp="M7",
            cwe="CWE-656",
            masvs="MASVS-RESILIENCE",
            confidence=Confidence.MEDIUM,
            description=(
                f"{len(app_classes)} application classes carry their original names "
                f"({obfuscated} look renamed, {ratio:.0%}), and "
                f"{with_source} retain their source file names. The app's structure, "
                "class names and method names are therefore readable to anyone who "
                "decompiles it — which takes one command. "
                "Obfuscation is not a security control and does not protect a secret "
                "that should not be in the binary at all; it raises the cost of "
                "understanding and repackaging the app, which matters most for "
                "licensing, cloning and tamper resistance."
            ),
            remediation=(
                "Enable R8 in release builds (`minifyEnabled true`) with a keep "
                "ruleset limited to what reflection genuinely needs. Verify the "
                "release APK afterwards — a keep rule that is too broad leaves the "
                "app effectively unobfuscated."
            ),
            evidence=[
                self.evidence(ctx, "classes.dex", f"class {name}", redact=False)
                for name in sorted(app_classes)[:10]
            ],
            metadata={
                "app_classes": len(app_classes),
                "renamed_ratio": round(ratio, 3),
                "classes_with_source_file": with_source,
            },
        )

    def _root_detection(self, ctx: ScanContext) -> Iterator[Finding]:
        if self._has_marker(ctx, _ROOT_MARKERS):
            return
        yield self.finding(
            ctx,
            rule_id="BIN-NO-ROOT-DETECTION",
            title="No root detection was found",
            severity=Severity.LOW,
            owasp="M7",
            cwe="CWE-693",
            masvs="MASVS-RESILIENCE",
            confidence=Confidence.MEDIUM,
            description=(
                "No root-detection logic was found in the package (no checks for the "
                "`su` binary, known superuser packages, Magisk or Xposed). On a "
                "rooted device the app's sandbox does not hold: its private files, "
                "its memory and its runtime behaviour are all open to inspection and "
                "modification. "
                "Reported as an absent hardening measure. Root detection is "
                "bypassable by an attacker who controls the device and should never "
                "be the only thing protecting an asset — but its absence means the "
                "app cannot even tell that it is running somewhere hostile."
            ),
            remediation=(
                "If the app handles payments, health data or DRM, add root detection "
                "(RootBeer, or Play Integrity API on Android) and decide what to do "
                "about a positive result — often degrading a feature rather than "
                "refusing to run. Keep the server the authority: a client-side check "
                "informs risk scoring, it does not enforce anything."
            ),
            evidence=[
                self.evidence(
                    ctx, ctx.package.file_name,
                    "no root-detection markers found in the package", redact=False,
                )
            ],
        )

    def _anti_debugging(self, ctx: ScanContext) -> Iterator[Finding]:
        if self._has_marker(ctx, _ANTI_DEBUG_MARKERS):
            return
        yield self.finding(
            ctx,
            rule_id="BIN-NO-ANTI-DEBUG",
            title="No anti-debugging checks were found",
            severity=Severity.LOW,
            owasp="M7",
            cwe="CWE-693",
            masvs="MASVS-RESILIENCE",
            confidence=Confidence.LOW,
            description=(
                "No runtime debugger detection was found (`Debug.isDebuggerConnected`, "
                "a TracerPid check, `ptrace`/`PT_DENY_ATTACH`). Attaching a debugger "
                "or a Frida script to a running app lets an attacker read decrypted "
                "data, change control flow and bypass client-side checks. "
                "Reported as an absent hardening measure — anti-debugging is "
                "bypassable and only raises cost."
            ),
            remediation=(
                "For an app protecting high-value assets, detect attached debuggers "
                "and instrumentation frameworks at runtime and report the signal to "
                "the server for risk scoring rather than only reacting on-device."
            ),
            evidence=[
                self.evidence(
                    ctx, ctx.package.file_name,
                    "no anti-debugging markers found in the package", redact=False,
                )
            ],
        )

    def _debug_symbols(self, ctx: ScanContext) -> Iterator[Finding]:
        if not ctx.android.native_libs:
            return
        yield self.finding(
            ctx,
            rule_id="BIN-NATIVE-LIBS",
            title=f"{len(ctx.android.native_libs)} native libraries are bundled",
            severity=Severity.INFO,
            owasp="M7",
            masvs="MASVS-CODE",
            confidence=Confidence.HIGH,
            description=(
                "The APK ships native `.so` libraries. Native code is outside the "
                "reach of this tool's bytecode analysis, so anything it does — its "
                "own network calls, its own crypto, its own storage — has not been "
                "examined here. Native code is also where memory-safety bugs live, "
                "which the managed layer cannot have."
            ),
            remediation=(
                "Review native libraries separately: confirm they are built with "
                "stack protector, RELRO and PIE, that symbols are stripped in release, "
                "and that their upstream versions are current."
            ),
            evidence=[
                self.evidence(ctx, lib, "bundled native library", redact=False)
                for lib in ctx.android.native_libs[:20]
            ],
            metadata={"libraries": ctx.android.native_libs[:100]},
        )

    def _ios_protections(self, ctx: ScanContext) -> Iterator[Finding]:
        macho = ctx.ios.macho
        if macho is None:
            return

        if not getattr(macho, "encrypted", False):
            yield self.finding(
                ctx,
                rule_id="BIN-IOS-NOT-ENCRYPTED",
                title="Main binary is not FairPlay-encrypted",
                severity=Severity.INFO,
                owasp="M7",
                masvs="MASVS-RESILIENCE",
                confidence=Confidence.HIGH,
                description=(
                    "The Mach-O binary's encryption info indicates it is not "
                    "FairPlay-encrypted (cryptid = 0). This is expected for a "
                    "development or enterprise build, and for any IPA that has "
                    "already been decrypted; App Store copies are encrypted until "
                    "they are installed. It means the binary's code and strings can "
                    "be read directly with no decryption step."
                ),
                remediation=(
                    "No action if this is a development build. Note that App Store "
                    "encryption is a distribution control, not a security boundary — "
                    "it is removed on-device and by any jailbroken dumper."
                ),
                evidence=[
                    self.evidence(ctx, "main binary", "cryptid = 0", redact=False)
                ],
            )

        if not self._has_marker(ctx, _JAILBREAK_MARKERS):
            yield self.finding(
                ctx,
                rule_id="BIN-NO-JAILBREAK-DETECTION",
                title="No jailbreak detection was found",
                severity=Severity.LOW,
                owasp="M7",
                cwe="CWE-693",
                masvs="MASVS-RESILIENCE",
                confidence=Confidence.MEDIUM,
                description=(
                    "No jailbreak-detection markers were found (no checks for Cydia, "
                    "MobileSubstrate, apt, or writability outside the sandbox). On a "
                    "jailbroken device the app's Keychain items, container files and "
                    "runtime are all reachable. Reported as an absent hardening "
                    "measure, not a defect."
                ),
                remediation=(
                    "For an app handling sensitive data, add jailbreak detection and "
                    "use the result to inform server-side risk decisions rather than "
                    "relying on it alone."
                ),
                evidence=[
                    self.evidence(
                        ctx, ctx.package.file_name,
                        "no jailbreak-detection markers found", redact=False,
                    )
                ],
            )

        if getattr(macho, "has_pie", None) is False:
            yield self.finding(
                ctx,
                rule_id="BIN-IOS-NO-PIE",
                title="Main binary is not position-independent",
                severity=Severity.MEDIUM,
                owasp="M7",
                cwe="CWE-119",
                masvs="MASVS-RESILIENCE",
                description=(
                    "The Mach-O header does not set MH_PIE, so the binary loads at a "
                    "fixed address and ASLR does not apply to its own code. That "
                    "makes any memory-corruption bug in the app substantially easier "
                    "to exploit reliably."
                ),
                remediation="Build with `-fPIE -pie`; Xcode enables this by default.",
                evidence=[
                    self.evidence(ctx, "main binary", "MH_PIE flag not set", redact=False)
                ],
            )

    @staticmethod
    def _has_marker(ctx: ScanContext, markers: tuple[str, ...]) -> bool:
        for _, value in ctx.all_strings():
            if any(marker in value for marker in markers):
                return True
        if ctx.android:
            for entry in ctx.android.all_classes():
                if any(marker in entry.name for marker in markers):
                    return True
            for dex in ctx.android.dex_files:
                for ref in dex.method_refs:
                    if any(marker in ref.name for marker in markers):
                        return True
        return False
