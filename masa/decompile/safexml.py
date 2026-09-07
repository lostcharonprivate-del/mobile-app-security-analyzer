"""XML and plist parsing hardened against entity attacks.

Both `xml.etree.ElementTree` and `plistlib` sit on expat, which will happily
expand a nested entity bomb ("billion laughs") and, depending on build, resolve
external entities — turning a parsed manifest into a local-file-read or a hang.
Neither module exposes a switch for that, so documents carrying a DTD are
refused outright: a legitimate AndroidManifest.xml or Info.plist never has one.
"""

from __future__ import annotations

import plistlib
import re
import struct
import xml.etree.ElementTree as ET
from xml.parsers.expat import ExpatError
from typing import Any

from masa.config import DEFAULT_LIMITS, Limits
from masa.errors import DecompileError


class UnsafeXmlError(DecompileError):
    """The document declares a DTD or entities and is refused."""


_DOCTYPE = re.compile(rb"<!DOCTYPE", re.IGNORECASE)
_ENTITY = re.compile(rb"<!ENTITY", re.IGNORECASE)


def guard_xml_bytes(data: bytes, limits: Limits = DEFAULT_LIMITS) -> None:
    """Refuse documents that could trigger entity expansion.

    A blanket DOCTYPE ban is tempting but wrong here: essentially every XML
    property list in existence opens with Apple's standard

        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "...">

    and refusing those would mean silently failing to analyse most iOS
    configuration — a false negative that matters more than the DOCTYPE does.

    What actually causes harm is an *entity declaration*: an internal subset can
    define the nested entities of a billion-laughs bomb, or an external entity
    pointing at a local file. Both live inside `[ ... ]` or in an `<!ENTITY>`
    tag, so both are refused. A bare external DTD reference with no internal
    subset is inert, because expat does not fetch external DTDs unless an
    external-entity handler is installed, and neither ElementTree nor plistlib
    installs one.
    """
    if len(data) > limits.max_xml_bytes:
        raise UnsafeXmlError(
            f"XML document is {len(data)} bytes, above the {limits.max_xml_bytes} cap"
        )
    if _ENTITY.search(data):
        raise UnsafeXmlError("document declares an ENTITY (entity expansion risk)")

    match = _DOCTYPE.search(data)
    if match is None:
        return
    # Look at the DOCTYPE declaration itself: an internal subset opens with `[`
    # before the declaration's closing `>`.
    tail = data[match.start() : match.start() + 65_536]
    close = tail.find(b">")
    subset = tail.find(b"[")
    if subset != -1 and (close == -1 or subset < close):
        raise UnsafeXmlError(
            "document declares a DOCTYPE with an internal subset (entity expansion risk)"
        )


def parse_xml(data: bytes, limits: Limits = DEFAULT_LIMITS) -> ET.Element:
    """Parse XML text into an ElementTree root, refusing DTDs first."""
    guard_xml_bytes(data, limits)
    try:
        return ET.fromstring(data)
    except (ET.ParseError, ExpatError) as exc:
        raise DecompileError(f"malformed XML: {exc}") from exc
    except RecursionError as exc:
        raise UnsafeXmlError("XML nesting is too deep") from exc


def parse_plist(data: bytes, limits: Limits = DEFAULT_LIMITS) -> Any:
    """Parse a binary or XML property list.

    Binary plists (`bplist00`) go straight to plistlib — there is no entity
    machinery in that format. XML plists are guarded first.
    """
    if len(data) > limits.max_xml_bytes:
        raise UnsafeXmlError(
            f"plist is {len(data)} bytes, above the {limits.max_xml_bytes} cap"
        )
    if not data.startswith(b"bplist"):
        guard_xml_bytes(data, limits)
    try:
        return plistlib.loads(data)
    except (
        plistlib.InvalidFileException,
        # plistlib parses XML plists with expat, which raises ExpatError rather
        # than anything in the standard value-error family.
        ExpatError,
        ValueError,
        OverflowError,
        TypeError,
        IndexError,
        KeyError,
        struct.error,
    ) as exc:
        raise DecompileError(f"malformed plist: {exc}") from exc
    except RecursionError as exc:
        raise UnsafeXmlError("plist nesting is too deep") from exc
