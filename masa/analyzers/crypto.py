"""Insufficient cryptography (M10).

Broken primitives, broken modes, and keys that are not secret. Cipher transform
strings are read out of the string pool and attributed to the method that loaded
them, so a finding names the class that calls `Cipher.getInstance("DES/ECB/…")`.
"""

from __future__ import annotations

import re
from typing import Iterable, Iterator

from masa.analyzers.base import Analyzer, register
from masa.context import ScanContext
from masa.models import Confidence, Evidence, Finding, Platform, Severity

# Cipher transformation strings, as passed to Cipher.getInstance.
_TRANSFORM = re.compile(
    r"^(?P<algo>[A-Za-z0-9_]{2,16})"
    r"(?:/(?P<mode>[A-Za-z0-9]{2,12})(?:/(?P<padding>[A-Za-z0-9]{2,20}))?)?$"
)

_BROKEN_CIPHERS = {
    "DES": ("56-bit keys are brute-forcible in hours on commodity hardware", Severity.HIGH),
    "DESEDE": ("Triple DES has a 64-bit block, making it vulnerable to Sweet32", Severity.MEDIUM),
    "3DES": ("Triple DES has a 64-bit block, making it vulnerable to Sweet32", Severity.MEDIUM),
    "RC2": ("RC2 is obsolete and considered broken", Severity.HIGH),
    "RC4": ("RC4 has statistical biases that leak plaintext; prohibited by RFC 7465", Severity.HIGH),
    "BLOWFISH": ("64-bit block size makes Blowfish vulnerable to birthday attacks", Severity.MEDIUM),
    "ARCFOUR": ("ARCFOUR is RC4 and is broken", Severity.HIGH),
}

_BROKEN_DIGESTS = {
    "MD5": ("MD5 collisions are trivial to generate", Severity.MEDIUM),
    "MD4": ("MD4 is comprehensively broken", Severity.HIGH),
    "MD2": ("MD2 is comprehensively broken", Severity.HIGH),
    "SHA1": ("SHA-1 collisions are practical (SHAttered, 2017)", Severity.MEDIUM),
    "SHA-1": ("SHA-1 collisions are practical (SHAttered, 2017)", Severity.MEDIUM),
}

# Digest algorithms that are fine as checksums but wrong for password storage.
_PASSWORD_HASH_MARKERS = ("password", "passwd", "pwd", "credential")

_WEAK_MODES = {
    "ECB": (
        "ECB encrypts identical plaintext blocks to identical ciphertext blocks, so "
        "structure in the data survives encryption",
        Severity.HIGH,
    ),
}

_STRONG_KDFS = (
    "PBKDF2", "bcrypt", "scrypt", "Argon2", "PBEWith",
)


@register
class CryptoAnalyzer(Analyzer):
    name = "crypto"
    description = "Weak ciphers, broken modes, hardcoded keys and predictable randomness"
    platforms = (Platform.ANDROID, Platform.IOS)

    def analyze(self, ctx: ScanContext) -> Iterable[Finding]:
        yield from self._weak_transformations(ctx)
        yield from self._weak_digests(ctx)
        yield from self._predictable_random(ctx)
        yield from self._hardcoded_key_material(ctx)

    def _weak_transformations(self, ctx: ScanContext) -> Iterator[Finding]:
        broken: dict[str, list[Evidence]] = {}
        ecb: list[Evidence] = []
        no_mode: list[Evidence] = []

        for location, value in ctx.all_strings():
            match = _TRANSFORM.match(value.strip())
            if not match:
                continue
            algo = (match.group("algo") or "").upper()
            mode = (match.group("mode") or "").upper()
            padding = match.group("padding")

            if algo in _BROKEN_CIPHERS:
                broken.setdefault(algo, []).append(
                    self.evidence(ctx, location, value, redact=False)
                )
            if mode == "ECB":
                ecb.append(self.evidence(ctx, location, value, redact=False))
            # `Cipher.getInstance("AES")` silently means AES/ECB/PKCS5Padding.
            elif algo == "AES" and not mode and padding is None:
                no_mode.append(self.evidence(ctx, location, value, redact=False))

        for algo, evidence in sorted(broken.items()):
            reason, severity = _BROKEN_CIPHERS[algo]
            yield self.finding(
                ctx,
                rule_id=f"CRY-WEAK-CIPHER-{algo}",
                title=f"Broken cipher algorithm in use: {algo}",
                severity=severity,
                owasp="M10",
                cwe="CWE-327",
                masvs="MASVS-CRYPTO",
                description=(
                    f"The package requests the `{algo}` cipher. {reason}. Data "
                    "encrypted with it should be treated as recoverable by anyone "
                    "who obtains the ciphertext."
                ),
                remediation=(
                    "Use AES-256 in an authenticated mode (GCM, or CBC with a "
                    "separate HMAC). Re-encrypt any stored data that was protected "
                    "with the broken algorithm — changing the code does not fix "
                    "ciphertext already on devices."
                ),
                evidence=evidence,
                references=["https://cwe.mitre.org/data/definitions/327.html"],
            )

        if ecb:
            reason, severity = _WEAK_MODES["ECB"]
            yield self.finding(
                ctx,
                rule_id="CRY-ECB-MODE",
                title="Block cipher used in ECB mode",
                severity=severity,
                owasp="M10",
                cwe="CWE-327",
                masvs="MASVS-CRYPTO",
                description=(
                    f"A cipher is configured for ECB mode. {reason}. The classic "
                    "demonstration is an encrypted bitmap in which the original "
                    "image is still recognisable. ECB also provides no integrity, so "
                    "an attacker can reorder or replay blocks."
                ),
                remediation=(
                    "Use GCM, which provides both confidentiality and integrity, with "
                    "a unique nonce per encryption. If GCM is unavailable, use CBC "
                    "with a random IV and authenticate the ciphertext with a separate "
                    "HMAC key."
                ),
                evidence=ecb,
                references=["https://cwe.mitre.org/data/definitions/327.html"],
            )

        if no_mode:
            yield self.finding(
                ctx,
                rule_id="CRY-DEFAULT-MODE",
                title="Cipher requested without an explicit mode (defaults to ECB)",
                severity=Severity.HIGH,
                owasp="M10",
                cwe="CWE-327",
                masvs="MASVS-CRYPTO",
                confidence=Confidence.MEDIUM,
                description=(
                    "`Cipher.getInstance(\"AES\")` is used without naming a mode. The "
                    "JCA provider then picks its default, which on Android is "
                    "`AES/ECB/PKCS5Padding` — so the code gets ECB without ever "
                    "saying so, along with everything wrong with ECB."
                ),
                remediation=(
                    "Always pass a full transformation string, e.g. "
                    "`Cipher.getInstance(\"AES/GCM/NoPadding\")`."
                ),
                evidence=no_mode,
            )

    def _weak_digests(self, ctx: ScanContext) -> Iterator[Finding]:
        found: dict[str, list[Evidence]] = {}
        for location, value in ctx.all_strings():
            key = value.strip().upper().replace("-", "")
            if key in {k.replace("-", "") for k in _BROKEN_DIGESTS}:
                canonical = "SHA1" if key == "SHA1" else key
                found.setdefault(canonical, []).append(
                    self.evidence(ctx, location, value.strip(), redact=False)
                )

        for algo, evidence in sorted(found.items()):
            reason, severity = _BROKEN_DIGESTS.get(algo, ("weak digest", Severity.MEDIUM))
            yield self.finding(
                ctx,
                rule_id=f"CRY-WEAK-HASH-{algo}",
                title=f"Weak hash algorithm in use: {algo}",
                severity=severity,
                owasp="M10",
                cwe="CWE-328",
                masvs="MASVS-CRYPTO",
                confidence=Confidence.MEDIUM,
                description=(
                    f"The package requests `{algo}`. {reason}. This matters wherever "
                    "the hash is relied on for integrity or identity — signature "
                    "verification, tamper checks, deduplication of security-relevant "
                    "data. It is not a problem where the hash is only a "
                    "non-security checksum or cache key, so confirm how it is used."
                ),
                remediation=(
                    "Use SHA-256 or SHA-3 for integrity and identity. For password "
                    "storage no plain digest is appropriate — use Argon2id, scrypt "
                    "or PBKDF2 with a per-user salt and a high iteration count."
                ),
                evidence=evidence,
                references=["https://cwe.mitre.org/data/definitions/328.html"],
            )

    def _predictable_random(self, ctx: ScanContext) -> Iterator[Finding]:
        if not ctx.android:
            return
        evidence: list[Evidence] = []
        for invocation in ctx.android.invocations_by_name(
            "setSeed", receivers=("SecureRandom", "Random")
        ):
            evidence.append(
                self.evidence(
                    ctx, invocation.site.location,
                    "SecureRandom.setSeed(…) — replaces system entropy", redact=False,
                )
            )
        if not evidence:
            return
        yield self.finding(
            ctx,
            rule_id="CRY-SEEDED-RANDOM",
            title="SecureRandom is explicitly seeded",
            severity=Severity.HIGH,
            owasp="M10",
            cwe="CWE-336",
            masvs="MASVS-CRYPTO",
            confidence=Confidence.MEDIUM,
            description=(
                "`setSeed` is called on a SecureRandom instance. A correctly "
                "constructed SecureRandom is already seeded from the system entropy "
                "pool; supplying a seed can only reduce entropy, and when the seed is "
                "a constant every value the generator produces is reproducible by "
                "anyone reading the code. Keys, IVs, nonces and session identifiers "
                "derived from it become predictable."
            ),
            remediation=(
                "Construct `new SecureRandom()` and use it directly without seeding. "
                "Where a deterministic stream is genuinely needed for testing, keep "
                "that path out of production builds."
            ),
            evidence=evidence,
            references=["https://cwe.mitre.org/data/definitions/336.html"],
        )

    def _hardcoded_key_material(self, ctx: ScanContext) -> Iterator[Finding]:
        """Byte arrays and strings used as keys or IVs that ship with the app."""
        if not ctx.android:
            return
        evidence: list[Evidence] = []
        for entry in ctx.android.all_classes():
            for field_name in entry.static_field_names:
                lowered = field_name.lower()
                if lowered in ("key", "iv", "secret_key", "secretkey", "aes_key", "enc_key") or (
                    lowered.endswith(("_key", "_iv")) and len(lowered) <= 24
                ):
                    evidence.append(
                        self.evidence(
                            ctx,
                            f"{entry.name}.{field_name}",
                            f"static field `{field_name}` initialised in the class",
                            redact=False,
                        )
                    )
        if not evidence:
            return
        yield self.finding(
            ctx,
            rule_id="CRY-HARDCODED-KEY",
            title="Cryptographic key or IV appears to be hardcoded",
            severity=Severity.HIGH,
            owasp="M10",
            cwe="CWE-321",
            masvs="MASVS-CRYPTO",
            confidence=Confidence.MEDIUM,
            description=(
                "Static fields named like key or IV material are initialised inside "
                "the shipped classes. A key compiled into the app is the same for "
                "every install and is recoverable by anyone who unpacks it, so the "
                "encryption it performs protects data from nobody who has the app. "
                "A fixed IV is a related but distinct problem: reusing an IV across "
                "messages breaks CBC's semantic security and is catastrophic in GCM, "
                "where nonce reuse leaks the authentication key."
            ),
            remediation=(
                "Generate keys on the device and store them in the Android Keystore "
                "(or the iOS Keychain / Secure Enclave) so the private material never "
                "exists in the app's own bytes. Generate a fresh random IV or nonce "
                "for every encryption and transmit it alongside the ciphertext — it "
                "is not secret, but it must never repeat."
            ),
            evidence=evidence,
            references=["https://cwe.mitre.org/data/definitions/321.html"],
        )
