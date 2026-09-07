"""AndroidManifest.xml configuration and component-exposure checks.

Covers M8 (security misconfiguration) for the build-level flags, and M3
(insecure authorization) for components any other app on the device can reach.
"""

from __future__ import annotations

from typing import Iterable, Iterator

from masa.analyzers.base import Analyzer, register
from masa.context import ScanContext
from masa.decompile.axml import Element
from masa.models import Confidence, Evidence, Finding, Platform, Severity

# Permissions whose presence is worth calling out on its own.
_SENSITIVE_PERMISSIONS = {
    "android.permission.READ_SMS": "read the user's text messages",
    "android.permission.RECEIVE_SMS": "intercept incoming text messages",
    "android.permission.SEND_SMS": "send texts at the user's expense",
    "android.permission.READ_CONTACTS": "read the user's address book",
    "android.permission.ACCESS_FINE_LOCATION": "track the user's precise location",
    "android.permission.ACCESS_BACKGROUND_LOCATION": "track location in the background",
    "android.permission.RECORD_AUDIO": "record from the microphone",
    "android.permission.CAMERA": "capture photos and video",
    "android.permission.READ_CALL_LOG": "read who the user has called",
    "android.permission.READ_PHONE_STATE": "read device and SIM identifiers",
    "android.permission.REQUEST_INSTALL_PACKAGES": "install other applications",
    "android.permission.SYSTEM_ALERT_WINDOW": "draw over other apps",
    "android.permission.QUERY_ALL_PACKAGES": "enumerate every installed app",
    "android.permission.MANAGE_EXTERNAL_STORAGE": "read and write all shared storage",
}

_COMPONENT_KINDS = ("activity", "activity-alias", "service", "receiver", "provider")

# Actions that are only delivered by the system, so an exported receiver
# listening for them is not reachable by an arbitrary third-party app.
_SYSTEM_ONLY_ACTIONS = frozenset(
    {
        "android.intent.action.BOOT_COMPLETED",
        "android.intent.action.MY_PACKAGE_REPLACED",
        "android.intent.action.PACKAGE_REPLACED",
        "android.net.conn.CONNECTIVITY_CHANGE",
        "android.intent.action.MAIN",
    }
)


def _is_launcher(element: Element) -> bool:
    for filt in element.find_all("intent-filter"):
        actions = {a.get("android:name") for a in filt.find_all("action")}
        categories = {c.get("android:name") for c in filt.find_all("category")}
        if (
            "android.intent.action.MAIN" in actions
            and "android.intent.category.LAUNCHER" in categories
        ):
            return True
    return False


def _exported(element: Element) -> bool:
    declared = element.get_bool("android:exported")
    if declared is not None:
        return declared
    return bool(element.find_all("intent-filter"))


def _guarded(element: Element) -> bool:
    """True when some permission attribute gates access to the component."""
    return any(
        element.get(attr)
        for attr in (
            "android:permission",
            "android:readPermission",
            "android:writePermission",
        )
    )


@register
class ManifestAnalyzer(Analyzer):
    name = "manifest"
    description = "Android manifest flags, exported components and permissions"
    platforms = (Platform.ANDROID,)

    def analyze(self, ctx: ScanContext) -> Iterable[Finding]:
        if not ctx.android or not ctx.android.manifest:
            return
        doc = ctx.android.manifest
        if doc.root is None:
            return

        yield from self._debuggable(ctx, doc)
        yield from self._backup(ctx, doc)
        yield from self._test_only(ctx, doc)
        yield from self._exported_components(ctx, doc)
        yield from self._providers(ctx, doc)
        yield from self._task_hijacking(ctx, doc)
        yield from self._permissions(ctx, doc)
        yield from self._custom_permissions(ctx, doc)
        yield from self._sdk_levels(ctx, doc)

    # -- M8: build flags ------------------------------------------------------

    def _debuggable(self, ctx: ScanContext, doc) -> Iterator[Finding]:
        for app in doc.find_all("application"):
            if app.get_bool("android:debuggable"):
                yield self.finding(
                    ctx,
                    rule_id="MAN-DEBUGGABLE",
                    title="Application is marked debuggable",
                    severity=Severity.CRITICAL,
                    owasp="M8",
                    cwe="CWE-489",
                    masvs="MASVS-RESILIENCE",
                    description=(
                        "`android:debuggable=\"true\"` is set on <application>. On any "
                        "device, anyone who can reach ADB can attach a debugger to "
                        "this process, read and modify its memory, call its methods "
                        "and extract whatever it holds — including keys the app "
                        "decrypts at runtime. It also lets `run-as` read the app's "
                        "private data directory without root."
                    ),
                    remediation=(
                        "Remove `android:debuggable` from the manifest entirely. The "
                        "Android build system sets it automatically for debug builds, "
                        "so it should never be written by hand in a release manifest."
                    ),
                    evidence=[
                        self.evidence(
                            ctx,
                            "AndroidManifest.xml",
                            'android:debuggable="true"',
                            line=app.line or None,
                            redact=False,
                        )
                    ],
                    references=["https://cwe.mitre.org/data/definitions/489.html"],
                )

    def _backup(self, ctx: ScanContext, doc) -> Iterator[Finding]:
        for app in doc.find_all("application"):
            allow_backup = app.get_bool("android:allowBackup")
            # allowBackup defaults to true when the attribute is absent.
            if allow_backup is False:
                continue
            explicit = allow_backup is True
            has_rules = bool(
                app.get("android:fullBackupContent")
                or app.get("android:dataExtractionRules")
            )
            if has_rules:
                continue
            yield self.finding(
                ctx,
                rule_id="MAN-ALLOW-BACKUP",
                title="Application data can be extracted through Android Backup",
                severity=Severity.MEDIUM,
                owasp="M8",
                cwe="CWE-530",
                masvs="MASVS-STORAGE",
                confidence=Confidence.HIGH if explicit else Confidence.MEDIUM,
                description=(
                    (
                        "`android:allowBackup=\"true\"` is set"
                        if explicit
                        else "`android:allowBackup` is not set, and it defaults to true"
                    )
                    + ", and no backup rules restrict what is included. Anyone with "
                    "physical access and USB debugging can run `adb backup` to pull "
                    "the app's private data directory off the device, and the data "
                    "also flows to cloud backup. Whatever the app stores locally — "
                    "session tokens, cached PII — leaves the device with it."
                ),
                remediation=(
                    "Set `android:allowBackup=\"false\"`, or keep backup enabled and "
                    "exclude sensitive files with `android:dataExtractionRules` "
                    "(API 31+) and `android:fullBackupContent`."
                ),
                evidence=[
                    self.evidence(
                        ctx,
                        "AndroidManifest.xml",
                        f'android:allowBackup="{"true" if explicit else "(default true)"}"',
                        line=app.line or None,
                        redact=False,
                    )
                ],
                references=["https://cwe.mitre.org/data/definitions/530.html"],
            )

    def _test_only(self, ctx: ScanContext, doc) -> Iterator[Finding]:
        for app in doc.find_all("application"):
            if app.get_bool("android:testOnly"):
                yield self.finding(
                    ctx,
                    rule_id="MAN-TEST-ONLY",
                    title="Application is flagged testOnly",
                    severity=Severity.MEDIUM,
                    owasp="M8",
                    cwe="CWE-489",
                    masvs="MASVS-RESILIENCE",
                    description=(
                        "`android:testOnly=\"true\"` marks a build that was never "
                        "meant to be distributed. Such builds permit operations that "
                        "release builds do not, and their presence in a shipped "
                        "package indicates a build-pipeline mistake."
                    ),
                    remediation="Remove `android:testOnly` before building for release.",
                    evidence=[
                        self.evidence(
                            ctx, "AndroidManifest.xml", 'android:testOnly="true"',
                            line=app.line or None, redact=False,
                        )
                    ],
                )

    # -- M3: component exposure ----------------------------------------------

    def _exported_components(self, ctx: ScanContext, doc) -> Iterator[Finding]:
        grouped: dict[str, list[Evidence]] = {}
        for kind in _COMPONENT_KINDS:
            if kind == "provider":
                continue  # providers get their own, higher-severity rule
            for element in doc.find_all(kind):
                if not _exported(element) or _guarded(element):
                    continue
                if kind in ("activity", "activity-alias") and _is_launcher(element):
                    continue  # the launcher entry point is exported by definition
                if kind == "receiver" and self._system_only(element):
                    continue
                name = element.get("android:name") or "(unnamed)"
                grouped.setdefault(kind, []).append(
                    self.evidence(
                        ctx,
                        "AndroidManifest.xml",
                        f"<{kind} android:name=\"{name}\" android:exported=\"true\"> "
                        "with no android:permission",
                        line=element.line or None,
                        redact=False,
                    )
                )

        for kind, evidence in grouped.items():
            severity = Severity.HIGH if kind in ("service", "activity") else Severity.MEDIUM
            yield self.finding(
                ctx,
                rule_id=f"MAN-EXPORTED-{kind.upper().replace('-', '_')}",
                title=f"Exported {kind} with no permission check ({len(evidence)})",
                severity=severity,
                owasp="M3",
                cwe="CWE-926",
                masvs="MASVS-PLATFORM",
                description=(
                    f"{len(evidence)} {kind} component(s) are exported without an "
                    "`android:permission` attribute. Any other app installed on the "
                    "device — including one the user installed by accident — can "
                    "start them directly and supply arbitrary Intent extras. If the "
                    "component performs a privileged action, or trusts data from the "
                    "Intent, that is a way in that bypasses the app's own UI and "
                    "whatever authentication it does."
                ),
                remediation=(
                    "Set `android:exported=\"false\"` on anything that does not need "
                    "to be reachable from other apps. Where it must stay exported, "
                    "guard it with a signature-level `android:permission` and "
                    "validate every value read from the incoming Intent."
                ),
                evidence=evidence,
                references=[
                    "https://cwe.mitre.org/data/definitions/926.html",
                    "https://developer.android.com/guide/topics/manifest/activity-element#exported",
                ],
                metadata={"component_kind": kind, "count": len(evidence)},
            )

    @staticmethod
    def _system_only(element: Element) -> bool:
        actions: set[str] = set()
        for filt in element.find_all("intent-filter"):
            actions |= {
                a.get("android:name") or "" for a in filt.find_all("action")
            }
        return bool(actions) and actions <= _SYSTEM_ONLY_ACTIONS

    def _providers(self, ctx: ScanContext, doc) -> Iterator[Finding]:
        for element in doc.find_all("provider"):
            if not _exported(element):
                continue
            authorities = element.get("android:authorities") or "(none)"
            name = element.get("android:name") or "(unnamed)"
            grants = element.get_bool("android:grantUriPermissions")

            if not _guarded(element):
                yield self.finding(
                    ctx,
                    rule_id="MAN-EXPORTED-PROVIDER",
                    title="Content provider is exported without a permission",
                    severity=Severity.HIGH,
                    owasp="M3",
                    cwe="CWE-926",
                    masvs="MASVS-PLATFORM",
                    description=(
                        f"The content provider `{name}` (authority `{authorities}`) "
                        "is exported and no read or write permission guards it. Any "
                        "app on the device can query, insert into and delete from "
                        "whatever it exposes. Providers usually sit directly on top "
                        "of the app's database, so this is often equivalent to "
                        "handing out the app's stored data."
                    ),
                    remediation=(
                        "Set `android:exported=\"false\"` unless other apps genuinely "
                        "need this data. If they do, declare `android:readPermission` "
                        "and `android:writePermission`, and make the provider's own "
                        "query handling parameterise every selection argument."
                    ),
                    evidence=[
                        self.evidence(
                            ctx, "AndroidManifest.xml",
                            f'<provider android:name="{name}" '
                            f'android:authorities="{authorities}" android:exported="true">',
                            line=element.line or None, redact=False,
                        )
                    ],
                )

            if grants and not _guarded(element):
                yield self.finding(
                    ctx,
                    rule_id="MAN-PROVIDER-GRANT-URI",
                    title="Exported provider grants URI permissions",
                    severity=Severity.MEDIUM,
                    owasp="M3",
                    cwe="CWE-926",
                    masvs="MASVS-PLATFORM",
                    description=(
                        f"`{name}` sets `android:grantUriPermissions=\"true\"` while "
                        "exported and unguarded. Temporary URI grants let a caller "
                        "hand access to a specific record on to a third app, widening "
                        "the reach of any data the provider exposes."
                    ),
                    remediation=(
                        "Restrict grants with `<grant-uri-permission android:path…>` "
                        "elements rather than allowing them across the whole provider."
                    ),
                    evidence=[
                        self.evidence(
                            ctx, "AndroidManifest.xml",
                            f'{name}: android:grantUriPermissions="true"',
                            line=element.line or None, redact=False,
                        )
                    ],
                )

    def _task_hijacking(self, ctx: ScanContext, doc) -> Iterator[Finding]:
        """taskAffinity + singleTask is the StrandHogg task-reparenting surface."""
        evidence: list[Evidence] = []
        package = doc.root.get("package") if doc.root else None
        for element in doc.find_all("activity"):
            affinity = element.get("android:taskAffinity")
            launch_mode = element.get("android:launchMode")
            name = element.get("android:name") or "(unnamed)"
            risky_affinity = affinity is not None and affinity != package and affinity != ""
            if risky_affinity or launch_mode in ("singleTask", "2"):
                evidence.append(
                    self.evidence(
                        ctx, "AndroidManifest.xml",
                        f'{name}: taskAffinity="{affinity}" launchMode="{launch_mode}"',
                        line=element.line or None, redact=False,
                    )
                )
        if evidence:
            yield self.finding(
                ctx,
                rule_id="MAN-TASK-AFFINITY",
                title="Activity task configuration allows task hijacking",
                severity=Severity.MEDIUM,
                owasp="M8",
                cwe="CWE-940",
                masvs="MASVS-PLATFORM",
                confidence=Confidence.MEDIUM,
                description=(
                    "Activities declare a custom `taskAffinity` or use "
                    "`launchMode=\"singleTask\"`. A malicious app that declares the "
                    "same affinity can have its own activity placed into this app's "
                    "task, so the screen the user sees after switching back is under "
                    "the attacker's control — the basis of the StrandHogg phishing "
                    "technique."
                ),
                remediation=(
                    "Set `android:taskAffinity=\"\"` on activities that handle "
                    "sensitive input, and avoid `singleTask` unless the launch "
                    "semantics are genuinely required."
                ),
                evidence=evidence,
            )

    # -- M6/M8: permissions ---------------------------------------------------

    def _permissions(self, ctx: ScanContext, doc) -> Iterator[Finding]:
        requested = {
            name
            for element in doc.find_all("uses-permission")
            if (name := element.get("android:name"))
        }
        sensitive = sorted(requested & _SENSITIVE_PERMISSIONS.keys())
        if not sensitive:
            return
        yield self.finding(
            ctx,
            rule_id="MAN-SENSITIVE-PERMISSIONS",
            title=f"Application requests {len(sensitive)} high-risk permissions",
            severity=Severity.LOW if len(sensitive) < 4 else Severity.MEDIUM,
            owasp="M6",
            cwe="CWE-250",
            masvs="MASVS-PRIVACY",
            confidence=Confidence.HIGH,
            description=(
                "The app requests permissions that give it access to personal data "
                "or powerful device capabilities: "
                + "; ".join(
                    f"`{name}` — {_SENSITIVE_PERMISSIONS[name]}" for name in sensitive
                )
                + ". Each is legitimate for some apps. Reported so the set can be "
                "checked against what the app actually does: a permission the "
                "feature set does not justify is both a privacy problem and extra "
                "attack surface if the app is compromised."
            ),
            remediation=(
                "Drop any permission not tied to a shipped feature. For the rest, "
                "request at the point of use rather than at launch, prefer the "
                "narrower variant where one exists (coarse over fine location, "
                "READ_MEDIA_* over broad storage), and make sure the privacy policy "
                "and store listing match."
            ),
            evidence=[
                self.evidence(
                    ctx, "AndroidManifest.xml",
                    f"uses-permission: {name}", redact=False,
                )
                for name in sensitive
            ],
            metadata={"permissions": sensitive, "total_requested": len(requested)},
        )

    def _custom_permissions(self, ctx: ScanContext, doc) -> Iterator[Finding]:
        weak: list[Evidence] = []
        for element in doc.find_all("permission"):
            level = (element.get("android:protectionLevel") or "normal").lower()
            name = element.get("android:name") or "(unnamed)"
            if level.startswith(("normal", "dangerous")) or level in ("0", "1"):
                weak.append(
                    self.evidence(
                        ctx, "AndroidManifest.xml",
                        f'<permission android:name="{name}" '
                        f'android:protectionLevel="{level}">',
                        line=element.line or None, redact=False,
                    )
                )
        if weak:
            yield self.finding(
                ctx,
                rule_id="MAN-WEAK-CUSTOM-PERMISSION",
                title="Custom permission uses a weak protection level",
                severity=Severity.MEDIUM,
                owasp="M3",
                cwe="CWE-280",
                masvs="MASVS-PLATFORM",
                description=(
                    "Custom permissions are declared with `normal` or `dangerous` "
                    "protection. `normal` is granted to any app that asks, without "
                    "the user seeing anything, and `dangerous` only asks the user. "
                    "Neither restricts *which* app gets it, so a permission used to "
                    "guard an exported component is not much of a guard."
                ),
                remediation=(
                    "Use `android:protectionLevel=\"signature\"` so only apps signed "
                    "with the same key can hold the permission."
                ),
                evidence=weak,
                references=["https://cwe.mitre.org/data/definitions/280.html"],
            )

    def _sdk_levels(self, ctx: ScanContext, doc) -> Iterator[Finding]:
        min_sdk_raw = ctx.app.min_sdk
        try:
            min_sdk = int(min_sdk_raw) if min_sdk_raw else None
        except ValueError:
            min_sdk = None
        if min_sdk is None or min_sdk >= 28:
            return
        yield self.finding(
            ctx,
            rule_id="MAN-LOW-MIN-SDK",
            title=f"minSdkVersion {min_sdk} keeps modern platform defaults off",
            severity=Severity.LOW if min_sdk >= 24 else Severity.MEDIUM,
            owasp="M8",
            cwe="CWE-1104",
            masvs="MASVS-PLATFORM",
            description=(
                f"The app supports API level {min_sdk}. Below API 28 cleartext HTTP "
                "is permitted by default, and below API 24 the system trusts "
                "user-installed CAs for the app's traffic, which is what makes "
                "casual interception with a proxy possible. Older levels also miss "
                "scoped storage and the stricter Intent-redirection rules."
            ),
            remediation=(
                "Raise `minSdkVersion` to at least 28 if the user base allows it. "
                "While supporting older levels, compensate explicitly: ship a "
                "network security config that disables cleartext and pins to the "
                "system CA store."
            ),
            evidence=[
                self.evidence(
                    ctx, "AndroidManifest.xml",
                    f'android:minSdkVersion="{min_sdk}"', redact=False,
                )
            ],
        )
