"""Credential patterns, shared by the secret scanner and the redaction layer.

These live in their own module because two consumers need them and neither should
import the other: `analyzers.secrets` uses them to *find* credentials, and
`redact` uses them to make sure no evidence snippet ever prints one in full.

Patterns are written without nested quantifiers so matching stays linear in the
length of the input — a hostile string cannot make the scanner hang.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from masa.models import Confidence, Severity


@dataclass(frozen=True)
class SecretRule:
    id: str
    name: str
    pattern: re.Pattern[str]
    severity: Severity
    confidence: Confidence = Confidence.HIGH
    cwe: str = "CWE-798"
    note: str = ""
    group: int = 0
    """Which capture group holds the secret itself."""


# Patterns are written without nested quantifiers so matching stays linear in the
# length of the input — a hostile string cannot make the scanner hang.
SECRET_RULES: tuple[SecretRule, ...] = (
    SecretRule(
        "SEC-AWS-AKID", "AWS access key ID",
        re.compile(r"\b((?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16})\b"),
        Severity.CRITICAL, group=1,
        note="AWS access key IDs are paired with a secret key; both are usually shipped together.",
    ),
    SecretRule(
        "SEC-AWS-SECRET", "AWS secret access key",
        re.compile(
            r"(?i)aws[_-]?(?:secret|sk)[_-]?(?:access)?[_-]?key\W{0,10}([A-Za-z0-9/+=]{40})"
        ),
        Severity.CRITICAL, group=1, cwe="CWE-798",
    ),
    SecretRule(
        "SEC-GCP-APIKEY", "Google API key",
        re.compile(r"\b(AIza[0-9A-Za-z_\-]{35})\b"),
        Severity.HIGH, group=1,
        note="Unrestricted Google API keys can be billed against by anyone who extracts them.",
    ),
    SecretRule(
        "SEC-GCP-SA", "Google service account credentials",
        re.compile(r"(\"type\"\s*:\s*\"service_account\")"),
        Severity.CRITICAL, group=1,
    ),
    SecretRule(
        "SEC-SLACK-TOKEN", "Slack token",
        re.compile(r"\b(xox[abprs]-[0-9A-Za-z-]{10,72})\b"),
        Severity.HIGH, group=1,
    ),
    SecretRule(
        "SEC-SLACK-HOOK", "Slack incoming webhook",
        re.compile(r"(https://hooks\.slack\.com/services/[A-Za-z0-9/_+-]{10,120})"),
        Severity.MEDIUM, group=1,
    ),
    SecretRule(
        "SEC-GITHUB-PAT", "GitHub token",
        re.compile(r"\b((?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,255})\b"),
        Severity.CRITICAL, group=1,
    ),
    SecretRule(
        "SEC-STRIPE", "Stripe secret key",
        re.compile(r"\b((?:sk|rk)_live_[0-9A-Za-z]{16,99})\b"),
        Severity.CRITICAL, group=1,
    ),
    SecretRule(
        "SEC-PRIVATE-KEY", "Private key material",
        re.compile(
            r"(-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----)"
        ),
        Severity.CRITICAL, group=1, cwe="CWE-321",
        note="A private key inside the package is available to every user of the app.",
    ),
    SecretRule(
        "SEC-JWT", "JSON Web Token",
        re.compile(r"\b(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})"),
        Severity.HIGH, group=1, cwe="CWE-522",
        note="A shipped JWT is a bearer credential; anyone holding it is that user until it expires.",
    ),
    SecretRule(
        "SEC-TWILIO", "Twilio credentials",
        re.compile(r"\b(SK[0-9a-fA-F]{32}|AC[0-9a-fA-F]{32})\b"),
        Severity.HIGH, group=1, confidence=Confidence.MEDIUM,
    ),
    SecretRule(
        "SEC-SENDGRID", "SendGrid API key",
        re.compile(r"\b(SG\.[A-Za-z0-9_-]{16,32}\.[A-Za-z0-9_-]{16,64})\b"),
        Severity.HIGH, group=1,
    ),
    SecretRule(
        "SEC-MAILGUN", "Mailgun API key",
        re.compile(r"\b(key-[0-9a-zA-Z]{32})\b"),
        Severity.HIGH, group=1, confidence=Confidence.MEDIUM,
    ),
    SecretRule(
        "SEC-SQUARE", "Square access token",
        re.compile(r"\b(sq0(?:atp|csp)-[0-9A-Za-z_-]{20,64})\b"),
        Severity.HIGH, group=1,
    ),
    SecretRule(
        "SEC-AZURE-CONN", "Azure storage connection string",
        re.compile(r"(AccountKey=[A-Za-z0-9+/=]{40,120})"),
        Severity.CRITICAL, group=1,
    ),
    SecretRule(
        "SEC-NPM", "npm access token",
        re.compile(r"\b(npm_[A-Za-z0-9]{36})\b"),
        Severity.HIGH, group=1,
    ),
    SecretRule(
        "SEC-URL-CREDS", "Credentials embedded in a URL",
        re.compile(r"\b([a-z][a-z0-9+.-]{1,15}://[^\s:/@\"']{1,64}:[^\s:/@\"']{1,64}@)"),
        Severity.HIGH, group=1, cwe="CWE-522",
    ),
    SecretRule(
        "SEC-GENERIC-ASSIGN", "Credential assigned in code or configuration",
        re.compile(
            r"""(?ix)
            \b(?:api[_-]?key|apikey|secret[_-]?key|client[_-]?secret|
               auth[_-]?token|access[_-]?token|password|passwd|
               db[_-]?password|private[_-]?key)\b
            \s* [:=] \s* ["']?
            ([^\s"'<>,;)}]{8,120})
            """
        ),
        Severity.HIGH, group=1, confidence=Confidence.MEDIUM,
    ),
)


# Strings that look random but are structural, not secret.
_SUPPRESS = (
    re.compile(r"^L[a-zA-Z0-9_$/]+;$"),                    # DEX type descriptor
    re.compile(r"^\([^)]*\)[A-Za-z\[/;$]+$"),              # method proto
    re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z0-9_]+){2,}$"),  # java package name
    re.compile(r"^[a-z][a-zA-Z0-9_]*(?:\.[A-Za-z0-9_$]+){2,}$"),  # fully-qualified class
    re.compile(r"^(?:/[A-Za-z0-9_.$-]+){2,}/?$"),          # file path
    re.compile(r"^(?:[A-Za-z]+/)+[A-Za-z0-9_$]+$"),        # internal class path
    re.compile(r"^#[0-9a-fA-F]{3,8}$"),                    # colour literal
    re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
               r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"),        # UUID
    re.compile(r"^(?:[A-Za-z0-9_]+\s){2,}"),               # prose
    re.compile(r"^https?://[^\s?#]+$"),                    # plain URL, no credential
    re.compile(r"^(?:android|androidx|kotlin|java|javax|com\.google|com\.android)\b"),
    re.compile(r"^[<@$]"),                                 # markup / annotation
    re.compile(r"^\.[A-Za-z]"),                            # relative class reference
    re.compile(r"^~~"),                                    # d8/R8 compiler marker
    re.compile(r"^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5,}$"),  # MAC / fingerprint bytes
    re.compile(r"^data:[a-z]+/"),                          # inline data URI
)

# Values that appear in every app and are documented placeholders.
_KNOWN_BENIGN = frozenset(
    {
        "AKIAIOSFODNN7EXAMPLE",  # AWS's own documentation example key
    }
)


# Paths and filenames: never credentials, and mangling them makes a report useless.
_LOOKS_LIKE_PATH = re.compile(
    r"(?i)\.(xml|json|txt|dex|arsc|plist|java|kt|kts|properties|so|jar|aar|pem|"
    r"apk|ipa|md|html?|js|css|png|jpg|webp|ttf|proto|gradle|pro|cfg|ini|yaml|yml)"
    r"(?::|$|/)"
)


def is_structural(value: str) -> bool:
    """True when a high-entropy string is program structure rather than a secret."""
    if _LOOKS_LIKE_PATH.search(value):
        return True
    return any(pattern.search(value) for pattern in _SUPPRESS)


