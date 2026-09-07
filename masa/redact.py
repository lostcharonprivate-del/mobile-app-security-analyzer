"""Redaction for report evidence.

A security report that prints working credentials has moved the secret from a
place one attacker had to reverse-engineer into a document that gets emailed
around. Evidence is therefore always redacted: enough to recognise and grep for
the value in the original package, never enough to use it.

Redaction runs in three passes, because relying on any one of them has been shown
to leak. A caller can name the exact secret; every known credential pattern is
masked wherever it appears; and any remaining credential-shaped assignment is
masked by keyword. The keyword pass alone missed values in prose like
"aws key AKIA… secret wJalr…", which is why the pattern pass exists.
"""

from __future__ import annotations

import re

from masa.patterns import SECRET_RULES, is_structural

_KEEP_HEAD = 4
_KEEP_TAIL = 2
_MIN_REDACT_LENGTH = 8

# `password = "hunter2"` and friends: a keyword, a separator, then the value.
_ASSIGNMENT = re.compile(
    r"""(?ix)
    \b(
        pass(?:wd|word)? | secret | token | api[_-]?key | apikey | auth |
        credential | private[_-]?key | client[_-]?secret | session
    )\b
    \s* [:=] \s*
    (?P<quote>["']?)
    (?P<value>[^\s"',;)]{4,})
    (?P=quote)
    """
)

# The same keywords followed by whitespace rather than a separator, which is how
# credentials appear inside log messages and concatenated strings.
_KEYWORD_ADJACENT = re.compile(
    r"""(?ix)
    \b(?:
        pass(?:wd|word)? | secret | token | api[_-]?key | apikey |
        credential | bearer
    )\b
    \s+ (?:is \s+ )?
    (?P<value>[A-Za-z0-9_\-./+=]{8,})
    """
)


def redact_secret(value: str) -> str:
    """Mask the middle of a secret, keeping a recognisable head and tail."""
    if not value:
        return ""
    if len(value) < _MIN_REDACT_LENGTH:
        return "*" * len(value)
    head = value[:_KEEP_HEAD]
    tail = value[-_KEEP_TAIL:]
    return f"{head}{'*' * min(12, len(value) - _KEEP_HEAD - _KEEP_TAIL)}{tail}"


def mask_known_secrets(text: str) -> str:
    """Mask anything matching a known credential pattern, wherever it appears.

    This is the pass that does not depend on surrounding syntax, so it catches
    credentials embedded in log messages, concatenated strings and prose.
    """
    for rule in SECRET_RULES:
        # The generic keyword rule is handled by the assignment passes below;
        # applying it here would mask the keyword as well as the value.
        if rule.id == "SEC-GENERIC-ASSIGN":
            continue

        def _replace(match: re.Match[str], _rule=rule) -> str:
            value = match.group(_rule.group)
            if not value or len(value) < _MIN_REDACT_LENGTH:
                return match.group(0)
            return match.group(0).replace(value, redact_secret(value))

        text = rule.pattern.sub(_replace, text)
    return text


# A single token that is itself the credential: "hunter2-super-secret-admin" has
# no separator for the assignment passes to key on, and matches no vendor pattern.
_SENSITIVE_TOKEN_WORD = re.compile(
    r"(?i)(pass(?:wd|word)?|secret|token|credential|apikey|api_key|auth|bearer|jwt)"
)
_LONE_TOKEN = re.compile(r"^[A-Za-z0-9_\-./+=:]{12,}$")


def redact_lone_token(text: str) -> str:
    """Mask a snippet that consists solely of one credential-shaped token.

    This is the safety net beneath the other passes: an analyzer that emits a raw
    string from the package as evidence cannot leak a credential just because the
    string carried no surrounding syntax to key on.
    """
    stripped = text.strip()
    if not _LONE_TOKEN.match(stripped):
        return text
    # Class names, file paths and method descriptors are what a reader needs to
    # act on the finding; masking them would make the report useless.
    if is_structural(stripped):
        return text
    if not _SENSITIVE_TOKEN_WORD.search(stripped) and _entropy(stripped) < 4.2:
        return text
    return text.replace(stripped, redact_secret(stripped))


def _entropy(value: str) -> float:
    from collections import Counter
    from math import log2

    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((c / length) * log2(c / length) for c in counts.values())


def redact_line(text: str) -> str:
    """Redact credential-shaped assignments and keyword-adjacent values."""

    def _replace(match: re.Match[str]) -> str:
        value = match.group("value")
        return match.group(0).replace(value, redact_secret(value))

    text = _ASSIGNMENT.sub(_replace, text)
    return _KEYWORD_ADJACENT.sub(_replace, text)


def snippet(
    text: str, limit: int = 160, secret: str | None = None, redact: bool = True
) -> str:
    """Build a one-line, length-capped, redacted excerpt for the report.

    `secret`, when given, is the exact substring to mask. Redaction does not stop
    there: every known pattern and every credential-shaped assignment in the text
    is masked as well, so a snippet cannot leak a *different* secret that happened
    to sit on the same line.
    """
    cleaned = " ".join(text.split())
    if redact:
        if secret:
            cleaned = cleaned.replace(secret, redact_secret(secret))
        cleaned = mask_known_secrets(cleaned)
        cleaned = redact_line(cleaned)
        cleaned = redact_lone_token(cleaned)
    if len(cleaned) > limit:
        cleaned = cleaned[: limit - 1] + "…"
    return cleaned
