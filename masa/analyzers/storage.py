"""Insecure local data storage (M9).

Where the app puts data on the device, and who else on the device can read it.
The Android checks lean on the resolved constant arguments recovered from the
bytecode, so `MODE_PRIVATE` is distinguished from `MODE_WORLD_READABLE` rather
than every preference write being flagged.
"""

from __future__ import annotations

from typing import Iterable, Iterator

from masa.analyzers.base import Analyzer, register
from masa.context import ScanContext
from masa.models import Confidence, Evidence, Finding, Platform, Severity

MODE_PRIVATE = 0
MODE_WORLD_READABLE = 1
MODE_WORLD_WRITEABLE = 2

# Method name -> index of the file-mode argument in the recorded arg tuple.
# Index 0 is the receiver for an instance call, so the mode of
# getSharedPreferences(String, int) sits at index 2.
_MODE_METHODS = {
    "getSharedPreferences": 2,
    "openFileOutput": 2,
    "openOrCreateDatabase": 2,
    "getDir": 2,
}

_EXTERNAL_STORAGE_METHODS = (
    "getExternalStorageDirectory",
    "getExternalStoragePublicDirectory",
    "getExternalFilesDir",
    "getExternalCacheDir",
    "getExternalMediaDirs",
)

_SQLCIPHER_MARKERS = ("net.sqlcipher", "net/sqlcipher", "SQLiteDatabase.loadLibs")
_ENCRYPTED_PREFS_MARKERS = (
    "androidx.security.crypto.EncryptedSharedPreferences",
    "androidx/security/crypto/EncryptedSharedPreferences",
    "EncryptedFile",
)


@register
class StorageAnalyzer(Analyzer):
    name = "storage"
    description = "Insecure local data storage: file modes, databases, external storage"
    platforms = (Platform.ANDROID, Platform.IOS)

    def analyze(self, ctx: ScanContext) -> Iterable[Finding]:
        if ctx.platform is Platform.ANDROID and ctx.android:
            yield from self._world_accessible(ctx)
            yield from self._external_storage(ctx)
            yield from self._unencrypted_database(ctx)
            yield from self._plaintext_preferences(ctx)
        if ctx.platform is Platform.IOS and ctx.ios:
            yield from self._ios_storage(ctx)

    # -- Android --------------------------------------------------------------

    def _world_accessible(self, ctx: ScanContext) -> Iterator[Finding]:
        readable: list[Evidence] = []
        writable: list[Evidence] = []

        for method, mode_index in _MODE_METHODS.items():
            for invocation in ctx.android.invocations_by_name(method):
                mode = invocation.arg(mode_index)
                if mode is None:
                    continue
                if mode & MODE_WORLD_WRITEABLE:
                    writable.append(
                        self.evidence(
                            ctx, invocation.site.location,
                            f"{method}(…, MODE_WORLD_WRITEABLE)", redact=False,
                        )
                    )
                if mode & MODE_WORLD_READABLE:
                    readable.append(
                        self.evidence(
                            ctx, invocation.site.location,
                            f"{method}(…, MODE_WORLD_READABLE)", redact=False,
                        )
                    )

        if readable:
            yield self.finding(
                ctx,
                rule_id="STO-WORLD-READABLE",
                title="App data is created world-readable",
                severity=Severity.HIGH,
                owasp="M9",
                cwe="CWE-732",
                masvs="MASVS-STORAGE",
                description=(
                    "Files or preferences are created with `MODE_WORLD_READABLE`. "
                    "That drops the per-app sandbox for those files: any other "
                    "application on the device can open and read them. The mode was "
                    "deprecated in API 17 and throws a SecurityException from API 24 "
                    "onward, so on modern devices this is both a data leak on old "
                    "installs and a crash on new ones."
                ),
                remediation=(
                    "Use `MODE_PRIVATE`. Where data genuinely has to be shared with "
                    "another app, expose it through a ContentProvider guarded by a "
                    "signature permission, or a FileProvider URI grant."
                ),
                evidence=readable,
                references=["https://cwe.mitre.org/data/definitions/732.html"],
            )

        if writable:
            yield self.finding(
                ctx,
                rule_id="STO-WORLD-WRITABLE",
                title="App data is created world-writable",
                severity=Severity.CRITICAL,
                owasp="M9",
                cwe="CWE-732",
                masvs="MASVS-STORAGE",
                description=(
                    "Files or preferences are created with `MODE_WORLD_WRITEABLE`. "
                    "Any other app on the device can overwrite them. If the app "
                    "reads configuration, a cached URL or a serialized object back "
                    "out of such a file, another app controls that input — which "
                    "turns a storage permission problem into code the app trusts "
                    "from an untrusted source."
                ),
                remediation=(
                    "Use `MODE_PRIVATE` and treat any externally-writable input as "
                    "untrusted if it cannot be removed."
                ),
                evidence=writable,
                references=["https://cwe.mitre.org/data/definitions/732.html"],
            )

    def _external_storage(self, ctx: ScanContext) -> Iterator[Finding]:
        evidence: list[Evidence] = []
        public_api = False
        for method in _EXTERNAL_STORAGE_METHODS:
            for site in ctx.android.sites_by_name(method):
                if method in (
                    "getExternalStorageDirectory",
                    "getExternalStoragePublicDirectory",
                ):
                    public_api = True
                evidence.append(
                    self.evidence(ctx, site.location, f"{method}()", redact=False)
                )
        if not evidence:
            return

        yield self.finding(
            ctx,
            rule_id="STO-EXTERNAL-STORAGE",
            title="Application writes to shared external storage",
            severity=Severity.MEDIUM if public_api else Severity.LOW,
            owasp="M9",
            cwe="CWE-922",
            masvs="MASVS-STORAGE",
            confidence=Confidence.MEDIUM,
            description=(
                "The app uses external-storage APIs"
                + (
                    ", including the public shared-storage roots "
                    "(`getExternalStorageDirectory` / "
                    "`getExternalStoragePublicDirectory`)"
                    if public_api
                    else ""
                )
                + ". External storage has no per-app access control: on older "
                "platform versions any app holding READ_EXTERNAL_STORAGE can read "
                "everything there, and files survive uninstall. Whether this matters "
                "depends on what is written — check the call sites listed below."
            ),
            remediation=(
                "Keep anything sensitive in internal storage (`getFilesDir()`), which "
                "is sandboxed per app. If a file must be shared, write it to app-"
                "specific external storage (`getExternalFilesDir()`) and hand other "
                "apps a FileProvider URI rather than a path."
            ),
            evidence=evidence,
            references=["https://cwe.mitre.org/data/definitions/922.html"],
        )

    def _unencrypted_database(self, ctx: ScanContext) -> Iterator[Finding]:
        db_sites = []
        for method in ("openOrCreateDatabase", "getWritableDatabase", "getReadableDatabase"):
            db_sites.extend(ctx.android.sites_by_name(method))
        if not db_sites:
            return
        if self._has_marker(ctx, _SQLCIPHER_MARKERS):
            return  # SQLCipher is present; the database is encrypted

        yield self.finding(
            ctx,
            rule_id="STO-UNENCRYPTED-DB",
            title="SQLite database is created without encryption",
            severity=Severity.MEDIUM,
            owasp="M9",
            cwe="CWE-311",
            masvs="MASVS-STORAGE",
            confidence=Confidence.MEDIUM,
            description=(
                "The app creates SQLite databases and no encryption layer "
                "(SQLCipher or an equivalent) was found in the package. The database "
                "file sits in the app's private directory in plaintext, which "
                "protects it from other apps but not from a rooted device, an ADB "
                "backup, a forensic image, or malware that has already escalated. "
                "Whether that matters depends on what the tables hold."
            ),
            remediation=(
                "For data that would matter if the device were lost, encrypt at rest: "
                "SQLCipher for the database, or Jetpack Security "
                "(`EncryptedFile` / `EncryptedSharedPreferences`) with the key held "
                "in the Android Keystore so it never exists in the app's memory as "
                "raw bytes."
            ),
            evidence=[
                self.evidence(ctx, site.location, "SQLite database created", redact=False)
                for site in db_sites
            ],
            references=["https://cwe.mitre.org/data/definitions/311.html"],
        )

    def _plaintext_preferences(self, ctx: ScanContext) -> Iterator[Finding]:
        """SharedPreferences keys whose names say they hold a credential."""
        if self._has_marker(ctx, _ENCRYPTED_PREFS_MARKERS):
            return
        put_sites = ctx.android.invocations_by_name(
            "putString", receivers=("SharedPreferences",)
        )
        if not put_sites:
            return

        sensitive_keys = sorted(
            {
                value
                for _, value in ctx.all_strings()
                if 3 <= len(value) <= 48 and _looks_sensitive_key(value)
            }
        )
        if not sensitive_keys:
            return

        yield self.finding(
            ctx,
            rule_id="STO-PLAINTEXT-PREFS",
            title="Credential-shaped keys are written to unencrypted SharedPreferences",
            severity=Severity.MEDIUM,
            owasp="M9",
            cwe="CWE-312",
            masvs="MASVS-STORAGE",
            confidence=Confidence.LOW,
            description=(
                "The app writes to SharedPreferences, no encrypted-preferences "
                "implementation was found, and the package contains key names that "
                "suggest credentials are among the values stored: "
                + ", ".join(f"`{k}`" for k in sensitive_keys[:8])
                + ". SharedPreferences are a plaintext XML file in the app's data "
                "directory. This rule matches on key *names*, so confirm what is "
                "actually written before acting on it."
            ),
            remediation=(
                "Store tokens and passwords with `EncryptedSharedPreferences` backed "
                "by an Android Keystore key, or keep only a short-lived token in "
                "memory and re-authenticate rather than persisting a long-lived one."
            ),
            evidence=[
                self.evidence(ctx, inv.site.location, "SharedPreferences.putString(…)", redact=False)
                for inv in put_sites[:10]
            ],
            metadata={"suspicious_keys": sensitive_keys[:20]},
            references=["https://cwe.mitre.org/data/definitions/312.html"],
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
        return False

    # -- iOS ------------------------------------------------------------------

    def _ios_storage(self, ctx: ScanContext) -> Iterator[Finding]:
        strings = {value for _, value in ctx.all_strings()}
        evidence: list[Evidence] = []

        uses_defaults = any(
            marker in value
            for value in strings
            for marker in ("NSUserDefaults", "standardUserDefaults", "UserDefaults")
        )
        sensitive = sorted({v for v in strings if 3 <= len(v) <= 48 and _looks_sensitive_key(v)})
        if uses_defaults and sensitive:
            evidence = [
                self.evidence(ctx, "main binary (strings)", f"NSUserDefaults key: {key}", redact=False)
                for key in sensitive[:10]
            ]
            yield self.finding(
                ctx,
                rule_id="STO-IOS-USERDEFAULTS",
                title="Credential-shaped keys used with NSUserDefaults",
                severity=Severity.MEDIUM,
                owasp="M9",
                cwe="CWE-312",
                masvs="MASVS-STORAGE",
                confidence=Confidence.LOW,
                description=(
                    "The binary references NSUserDefaults alongside key names that "
                    "look like credentials: "
                    + ", ".join(f"`{k}`" for k in sensitive[:8])
                    + ". NSUserDefaults is an unencrypted plist in the app container "
                    "and is included in iTunes and iCloud backups, so anything "
                    "stored there leaves the device with the backup."
                ),
                remediation=(
                    "Put credentials in the Keychain with an appropriate "
                    "`kSecAttrAccessible` value (`…WhenUnlockedThisDeviceOnly` for "
                    "anything that should not migrate to a new device), and keep "
                    "NSUserDefaults for non-sensitive preferences."
                ),
                evidence=evidence,
            )

        weak_keychain = sorted(
            {
                v
                for v in strings
                if v
                in (
                    "kSecAttrAccessibleAlways",
                    "kSecAttrAccessibleAlwaysThisDeviceOnly",
                )
            }
        )
        if weak_keychain:
            yield self.finding(
                ctx,
                rule_id="STO-IOS-KEYCHAIN-ACCESSIBLE",
                title="Keychain items are readable while the device is locked",
                severity=Severity.HIGH,
                owasp="M9",
                cwe="CWE-311",
                masvs="MASVS-STORAGE",
                description=(
                    "The binary references "
                    + ", ".join(f"`{k}`" for k in weak_keychain)
                    + ". These accessibility classes keep the item readable even "
                    "while the device is locked, so the data is not protected by "
                    "the user's passcode and is available to an attacker with the "
                    "locked device in hand."
                ),
                remediation=(
                    "Use `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` for "
                    "credentials, or "
                    "`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` when a "
                    "background task must reach the item."
                ),
                evidence=[
                    self.evidence(ctx, "main binary (strings)", key, redact=False)
                    for key in weak_keychain
                ],
            )


_SENSITIVE_KEY_WORDS = (
    "password", "passwd", "pwd", "secret", "token", "apikey", "api_key",
    "auth", "credential", "private_key", "privatekey", "session", "jwt",
    "refresh_token", "access_token", "pin_code", "passcode",
)


def _looks_sensitive_key(value: str) -> bool:
    lowered = value.lower()
    if any(ch in value for ch in " /\\(){}<>"):
        return False
    return any(word in lowered for word in _SENSITIVE_KEY_WORDS)
