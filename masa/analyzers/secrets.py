"""Hardcoded secret detection: named patterns plus Shannon entropy.

Two complementary passes. Named patterns catch credentials whose shape is known
(`AKIA...`, `ghp_...`, a PEM header) with high confidence. Entropy scoring catches
the rest — a 32-character random-looking literal that matches nothing in
particular — at lower confidence, with an explicit suppression list so that class
names, file paths and resource identifiers do not drown the signal.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import Iterable, Iterator

from masa.analyzers.base import Analyzer, register
from masa.context import ScanContext
from masa.models import Confidence, Evidence, Finding, Platform, Severity
from masa.redact import redact_secret
from masa.patterns import (
    SECRET_RULES,
    SecretRule,
    _KNOWN_BENIGN as KNOWN_BENIGN,
    is_structural,
)

_MAX_FINDINGS_PER_RULE = 40


def shannon_entropy(value: str) -> float:
    """Bits of entropy per character."""
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum(
        (count / length) * math.log2(count / length) for count in counts.values()
    )


@register
class SecretsAnalyzer(Analyzer):
    name = "secrets"
    description = "Hardcoded credentials, keys and tokens (pattern + entropy based)"
    platforms = (Platform.ANDROID, Platform.IOS)

    def analyze(self, ctx: ScanContext) -> Iterable[Finding]:
        # (rule, secret value) -> evidence, so one credential is one finding even
        # when it appears in a dozen places.
        buckets: dict[tuple[str, str], list[Evidence]] = {}
        rules_by_id = {rule.id: rule for rule in SECRET_RULES}

        for location, text in self._sources(ctx):
            for rule in SECRET_RULES:
                for match in rule.pattern.finditer(text):
                    value = match.group(rule.group)
                    if not value or value in KNOWN_BENIGN:
                        continue
                    if rule.id == "SEC-GENERIC-ASSIGN" and self._is_placeholder(value):
                        continue
                    key = (rule.id, value)
                    bucket = buckets.setdefault(key, [])
                    if len(bucket) < ctx.limits.max_evidence_per_finding:
                        bucket.append(
                            self.evidence(ctx, location, text, secret=value)
                        )

        yield from self._pattern_findings(ctx, buckets, rules_by_id)
        yield from self._named_secret_findings(ctx, {value for _, value in buckets})
        yield from self._entropy_findings(ctx, {value for _, value in buckets})

    def _sources(self, ctx: ScanContext) -> Iterator[tuple[str, str]]:
        """Every place a secret could hide, as (location, text) pairs."""
        for location, value in ctx.all_strings():
            yield location, value
        for text_file in ctx.text_files():
            for number, line in enumerate(text_file.lines(), start=1):
                if len(line) > ctx.limits.max_line_bytes:
                    line = line[: ctx.limits.max_line_bytes]
                yield f"{text_file.relative}:{number}", line

    @staticmethod
    def _is_placeholder(value: str) -> bool:
        """Filter the `password = "your-password-here"` class of match."""
        lowered = value.lower().strip("\"'")
        if lowered in {
            "null", "none", "true", "false", "password", "secret", "token",
            "changeme", "example", "test", "todo", "xxx", "placeholder",
        }:
            return True
        return bool(
            re.fullmatch(r"[<{\[$%].*[>}\]$%]", lowered)
            or re.search(r"your[_-]?\w*[_-]?(key|secret|token|password)", lowered)
            or re.fullmatch(r"[*x.]{4,}", lowered)
        )

    def _pattern_findings(
        self,
        ctx: ScanContext,
        buckets: dict[tuple[str, str], list[Evidence]],
        rules_by_id: dict[str, SecretRule],
    ) -> Iterator[Finding]:
        per_rule: Counter[str] = Counter()
        for (rule_id, value), evidence in sorted(buckets.items()):
            rule = rules_by_id[rule_id]
            per_rule[rule_id] += 1
            if per_rule[rule_id] > _MAX_FINDINGS_PER_RULE:
                continue
            detail = f" {rule.note}" if rule.note else ""
            yield self.finding(
                ctx,
                rule_id=rule_id,
                title=f"{rule.name} hardcoded in the package ({redact_secret(value)})",
                severity=rule.severity,
                owasp="M1",
                cwe=rule.cwe,
                masvs="MASVS-STORAGE",
                confidence=rule.confidence,
                description=(
                    f"A value matching the {rule.name} pattern is embedded in the "
                    f"shipped package and was found in {len(evidence)} location(s). "
                    "Anything inside an APK or IPA is readable by anyone who "
                    "downloads it — unpacking one takes seconds and no privileged "
                    f"access.{detail}"
                ),
                remediation=(
                    "Treat this credential as compromised and rotate it now. Move the "
                    "secret server-side and have the app request short-lived, scoped "
                    "tokens at runtime; if a key must reach the device, restrict it "
                    "by package name and signing certificate and give it the minimum "
                    "scope it needs."
                ),
                evidence=evidence,
                references=[
                    "https://owasp.org/www-project-mobile-top-10/2023-risks/m1-improper-credential-usage",
                    "https://cwe.mitre.org/data/definitions/798.html",
                ],
                metadata={"secret_length": len(value), "match_count": len(evidence)},
            )

    def _named_secret_findings(
        self, ctx: ScanContext, already_reported: set[str]
    ) -> Iterator[Finding]:
        """A resource or plist key whose name declares that its value is a secret.

        `<string name="db_password">…</string>` carries no pattern a regex would
        recognise and may not be high-entropy, but the developer has said what it
        is. This is one of the most common real hiding places for credentials.
        """
        candidates: list[tuple[str, str, str]] = []

        if ctx.android and ctx.android.resources:
            for entry in ctx.android.resources.strings:
                if _is_secret_name(entry.name) and _is_secret_value(entry.value):
                    candidates.append((entry.location, entry.name, entry.value))

        if ctx.ios:
            for rel, plist in ctx.ios.plists.items():
                for key, value in _iter_plist_strings(plist):
                    leaf = key.rsplit(".", 1)[-1]
                    if _is_secret_name(leaf) and _is_secret_value(value):
                        candidates.append((f"{rel}:{key}", leaf, value))

        for location, name, value in candidates:
            if value in already_reported:
                continue  # a named pattern already reported this exact value
            yield self.finding(
                ctx,
                rule_id="SEC-NAMED-RESOURCE",
                title=f"Resource `{name}` holds what its name says is a credential",
                severity=Severity.HIGH,
                owasp="M1",
                cwe="CWE-798",
                masvs="MASVS-STORAGE",
                confidence=Confidence.MEDIUM,
                description=(
                    f"The resource `{name}` at `{location}` contains a "
                    f"{len(value)}-character value. The name declares this is a "
                    "credential, and resource values are trivially readable — "
                    "`aapt dump` or any APK viewer prints them without decompiling "
                    "anything. String resources are a common place for keys to end "
                    "up because they feel like configuration rather than code."
                ),
                remediation=(
                    "Rotate this credential and remove it from the package. "
                    "Resource files, BuildConfig fields and Gradle properties all "
                    "end up inside the shipped artifact — none of them is a secret "
                    "store. Fetch the value from your backend at runtime instead."
                ),
                evidence=[self.evidence(ctx, location, value, secret=value)],
                metadata={"resource_name": name, "value_length": len(value)},
            )

    def _entropy_findings(
        self, ctx: ScanContext, already_reported: set[str]
    ) -> Iterator[Finding]:
        """Catch secrets that match no known vendor pattern."""
        config = ctx.config
        candidates: dict[str, list[Evidence]] = {}

        for location, value in ctx.all_strings():
            if not (config.min_entropy_length <= len(value) <= config.max_entropy_length):
                continue
            if value in already_reported or is_structural(value):
                continue
            if " " in value or "\n" in value:
                continue
            if shannon_entropy(value) < config.entropy_threshold:
                continue
            bucket = candidates.setdefault(value, [])
            if len(bucket) < ctx.limits.max_evidence_per_finding:
                bucket.append(self.evidence(ctx, location, value, secret=value))

        for index, (value, evidence) in enumerate(sorted(candidates.items())):
            if index >= _MAX_FINDINGS_PER_RULE:
                break
            entropy = shannon_entropy(value)
            yield self.finding(
                ctx,
                rule_id="SEC-ENTROPY",
                title="High-entropy string may be an embedded secret",
                severity=Severity.MEDIUM,
                owasp="M1",
                cwe="CWE-798",
                masvs="MASVS-STORAGE",
                confidence=Confidence.LOW,
                description=(
                    f"A {len(value)}-character string with {entropy:.2f} bits of "
                    "entropy per character was found in the package. That is the "
                    "statistical profile of a key or token rather than of ordinary "
                    "program text, though it matches no known credential format — "
                    "it could equally be a hash, a nonce or an encoded asset. "
                    "Confirm manually."
                ),
                remediation=(
                    "Check what this value is. If it is a credential, rotate it and "
                    "move it out of the package; if it is benign, no action is needed."
                ),
                evidence=evidence,
                metadata={
                    "entropy": round(entropy, 3),
                    "length": len(value),
                    "threshold": config.entropy_threshold,
                },
            )


_SECRET_NAME_WORDS = (
    "password", "passwd", "pwd", "secret", "token", "apikey", "api_key",
    "auth_key", "authkey", "private_key", "privatekey", "client_secret",
    "access_key", "accesskey", "credential", "signing_key", "encryption_key",
)

# Values that are obviously not a live credential.
_NON_SECRET_VALUES = frozenset(
    {"", "true", "false", "null", "none", "0", "1", "changeme", "todo"}
)


def _is_secret_name(name: str) -> bool:
    lowered = name.lower()
    return any(word in lowered for word in _SECRET_NAME_WORDS)


def _is_secret_value(value: str) -> bool:
    """Filter placeholders so an empty or templated resource is not reported."""
    stripped = value.strip()
    if len(stripped) < 6 or len(stripped) > 512:
        return False
    if stripped.lower() in _NON_SECRET_VALUES:
        return False
    # `${API_KEY}`, `@string/foo`, `YOUR_KEY_HERE` and similar are placeholders.
    if re.match(r"^[@${]", stripped) or re.search(r"(?i)your[_\- ]?\w*(key|secret|token)", stripped):
        return False
    return True


def _iter_plist_strings(value, prefix: str = ""):
    if isinstance(value, dict):
        for key, item in value.items():
            child = f"{prefix}.{key}" if prefix else str(key)
            yield from _iter_plist_strings(item, child)
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            yield from _iter_plist_strings(item, f"{prefix}[{index}]")
    elif isinstance(value, str):
        yield prefix, value
