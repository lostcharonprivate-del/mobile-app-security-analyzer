"""Exception hierarchy. Everything raised by the pipeline derives from MasaError."""

from __future__ import annotations


class MasaError(Exception):
    """Base class for all analyzer errors."""


class ValidationError(MasaError):
    """The input file is not an acceptable APK/IPA, or violates a safety limit."""


class HostileArchiveError(ValidationError):
    """The archive is actively malformed or malicious (zip bomb, path traversal)."""


class DecompileError(MasaError):
    """A decompilation step failed in a way that stops analysis of that artifact."""


class AnalysisTimeout(MasaError):
    """The scan exceeded its wall-clock budget."""
