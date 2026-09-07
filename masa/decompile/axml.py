"""Android binary XML (AXML) decoder — reads a compiled AndroidManifest.xml.

This is the pure-Python route that lets the tool parse a manifest with no apktool
and no androguard installed. It is also, deliberately, a hardened parser: every
chunk length is validated against the buffer, the element stack is depth-capped,
and a corrupt sub-chunk degrades to a partial tree instead of hanging.

Attribute names are resolved by string, and — for manifests whose attribute name
pool has been stripped — by Android's well-known attribute resource IDs.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from masa.decompile.binio import ParseError, Reader
from masa.decompile.stringpool import (
    RES_STRING_POOL_TYPE,
    StringPool,
    parse_string_pool,
)

RES_XML_TYPE = 0x0003
RES_XML_START_NAMESPACE = 0x0100
RES_XML_END_NAMESPACE = 0x0101
RES_XML_START_ELEMENT = 0x0102
RES_XML_END_ELEMENT = 0x0103
RES_XML_CDATA = 0x0104
RES_XML_RESOURCE_MAP_TYPE = 0x0180

TYPE_NULL = 0x00
TYPE_REFERENCE = 0x01
TYPE_ATTRIBUTE = 0x02
TYPE_STRING = 0x03
TYPE_FLOAT = 0x04
TYPE_DIMENSION = 0x05
TYPE_FRACTION = 0x06
TYPE_INT_DEC = 0x10
TYPE_INT_HEX = 0x11
TYPE_INT_BOOLEAN = 0x12

_MAX_DEPTH = 256
_MAX_ELEMENTS = 200_000
_ANDROID_NS = "http://schemas.android.com/apk/res/android"

# Android attribute resource IDs. A manifest can null out its attribute *names*
# while keeping these IDs (the platform resolves by ID), which is exactly what
# some packers do to defeat naive parsers. Resolving both ways closes that gap.
ATTR_RESOURCE_IDS: dict[int, str] = {
    0x01010000: "theme",
    0x01010001: "label",
    0x01010002: "icon",
    0x01010003: "name",
    0x01010006: "permission",
    0x01010007: "readPermission",
    0x01010008: "writePermission",
    0x01010009: "protectionLevel",
    0x0101000A: "process",
    0x0101000B: "taskAffinity",
    0x0101000C: "multiprocess",
    0x0101000D: "enabled",
    0x0101000E: "excludeFromRecents",
    0x0101000F: "authorities",
    0x01010010: "exported",
    0x01010011: "grantUriPermissions",
    0x01010014: "persistent",
    0x01010015: "hasCode",
    0x01010016: "allowTaskReparenting",
    0x01010018: "debuggable",
    0x0101001E: "value",
    0x0101001F: "resource",
    0x01010020: "mimeType",
    0x01010021: "scheme",
    0x01010022: "host",
    0x01010023: "port",
    0x01010024: "path",
    0x01010025: "pathPrefix",
    0x01010026: "pathPattern",
    0x01010027: "action",
    0x01010270: "minSdkVersion",
    0x01010271: "maxSdkVersion",
    0x01010280: "allowBackup",
    0x010102B7: "installLocation",
    0x01010354: "targetSdkVersion",
    0x010103A0: "windowSoftInputMode",
    0x01010445: "requiredForAllUsers",
    0x0101048F: "usesCleartextTraffic",
    0x010104EC: "usesCleartextTraffic",
    0x01010603: "fullBackupContent",
    0x0101061A: "directBootAware",
    0x01010887: "networkSecurityConfig",
    0x0101094D: "appComponentFactory",
    0x01010A8B: "allowClearUserData",
}


@dataclass
class Element:
    """One XML element in the decoded tree."""

    name: str
    attributes: dict[str, str] = field(default_factory=dict)
    """Attribute name (namespace prefix stripped to `android:` or bare) -> value."""

    children: list["Element"] = field(default_factory=list)
    line: int = 0
    parent: "Element | None" = field(default=None, repr=False, compare=False)

    def get(self, name: str, default: str | None = None) -> str | None:
        """Look up an attribute, tolerating the `android:` prefix being absent."""
        if name in self.attributes:
            return self.attributes[name]
        prefixed = f"android:{name}"
        if prefixed in self.attributes:
            return self.attributes[prefixed]
        bare = name.split(":", 1)[-1]
        return self.attributes.get(bare, default)

    def get_bool(self, name: str) -> bool | None:
        value = self.get(name)
        if value is None:
            return None
        return value.strip().lower() in ("true", "1")

    def iter(self, name: str | None = None):
        """Depth-first walk over this element and its descendants."""
        if name is None or self.name == name:
            yield self
        for child in self.children:
            yield from child.iter(name)

    def find_all(self, name: str) -> list["Element"]:
        return [el for el in self.iter(name) if el.name == name]

    def path(self) -> str:
        parts: list[str] = []
        node: Element | None = self
        while node is not None:
            parts.append(node.name)
            node = node.parent
        return "/".join(reversed(parts))


@dataclass
class AxmlDocument:
    root: Element | None
    strings: StringPool
    warnings: list[str] = field(default_factory=list)

    def iter(self, name: str | None = None):
        if self.root is None:
            return iter(())
        return self.root.iter(name)

    def find_all(self, name: str) -> list[Element]:
        return [] if self.root is None else self.root.find_all(name)


def looks_like_axml(data: bytes) -> bool:
    """Cheap sniff: compiled AXML starts with the RES_XML chunk header."""
    if len(data) < 8:
        return False
    return data[0] == 0x03 and data[1] == 0x00


def parse_axml(data: bytes) -> AxmlDocument:
    """Decode compiled binary XML into an element tree."""
    if len(data) < 8:
        raise ParseError("AXML buffer too small to contain a chunk header")

    reader = Reader(data)
    chunk_type = reader.u16()
    header_size = reader.u16()
    chunk_size = reader.u32()
    if chunk_type != RES_XML_TYPE:
        raise ParseError(f"not an AXML document (chunk type 0x{chunk_type:04x})")
    if header_size < 8:
        raise ParseError(f"implausible AXML header size {header_size}")
    # A truncated file is common with damaged APKs; parse what is actually there.
    end = min(chunk_size, len(data)) if chunk_size >= 8 else len(data)

    warnings: list[str] = []
    if chunk_size > len(data):
        warnings.append(
            f"AXML declares {chunk_size} bytes but file has {len(data)}; parsed partially"
        )

    pool = StringPool([], False)
    resource_map: list[int] = []
    root: Element | None = None
    stack: list[Element] = []
    element_count = 0

    offset = header_size
    while offset + 8 <= end:
        sub = Reader(data, offset)
        sub_type = sub.u16()
        sub_header = sub.u16()
        sub_size = sub.u32()
        if sub_size < 8 or offset + sub_size > end:
            warnings.append(
                f"chunk 0x{sub_type:04x} at {offset} declares {sub_size} bytes; stopping"
            )
            break

        try:
            if sub_type == RES_STRING_POOL_TYPE:
                pool, _ = parse_string_pool(data, offset)
            elif sub_type == RES_XML_RESOURCE_MAP_TYPE:
                resource_map = _parse_resource_map(data, offset, sub_header, sub_size)
            elif sub_type == RES_XML_START_ELEMENT:
                element_count += 1
                if element_count > _MAX_ELEMENTS:
                    warnings.append("element cap reached; tree truncated")
                    break
                element = _parse_start_element(
                    data, offset, sub_header, sub_size, pool, resource_map
                )
                if stack:
                    element.parent = stack[-1]
                    stack[-1].children.append(element)
                elif root is None:
                    root = element
                else:
                    # Multiple roots is malformed XML; keep the first and note it.
                    warnings.append("document declares more than one root element")
                stack.append(element)
                if len(stack) > _MAX_DEPTH:
                    warnings.append("element nesting cap reached; tree truncated")
                    break
            elif sub_type == RES_XML_END_ELEMENT:
                if stack:
                    stack.pop()
            elif sub_type in (
                RES_XML_START_NAMESPACE,
                RES_XML_END_NAMESPACE,
                RES_XML_CDATA,
            ):
                pass
        except ParseError as exc:
            warnings.append(f"chunk 0x{sub_type:04x} at {offset}: {exc}")

        offset += sub_size

    return AxmlDocument(root=root, strings=pool, warnings=warnings)


def _parse_resource_map(
    data: bytes, offset: int, header_size: int, chunk_size: int
) -> list[int]:
    start = offset + max(header_size, 8)
    count = max(0, (offset + chunk_size - start) // 4)
    count = min(count, 100_000)
    reader = Reader(data, start)
    return [reader.u32() for _ in range(count)]


def _parse_start_element(
    data: bytes,
    offset: int,
    header_size: int,
    chunk_size: int,
    pool: StringPool,
    resource_map: list[int],
) -> Element:
    reader = Reader(data, offset + 8)
    line = reader.u32()
    reader.u32()  # comment index

    body = offset + max(header_size, 16)
    reader.seek(body)
    _ns_index = reader.u32()
    name_index = reader.u32()
    attr_start = reader.u16()
    attr_size = reader.u16()
    attr_count = reader.u16()
    reader.u16()  # id index
    reader.u16()  # class index
    reader.u16()  # style index

    name = pool.get(name_index) or f"unknown_{name_index}"
    element = Element(name=name, line=line)

    if attr_size == 0 or attr_count == 0:
        return element
    if attr_size < 20:
        raise ParseError(f"attribute stride {attr_size} smaller than the 20-byte record")

    attrs_base = body + attr_start
    limit = offset + chunk_size
    if attrs_base + attr_count * attr_size > limit:
        # Trust the buffer, not the count: parse as many whole records as fit.
        attr_count = max(0, (limit - attrs_base) // attr_size)

    for index in range(attr_count):
        record = Reader(data, attrs_base + index * attr_size)
        ns_index = record.u32()
        attr_name_index = record.u32()
        raw_value_index = record.u32()
        record.u16()  # typed value size
        record.u8()  # res0
        data_type = record.u8()
        value_data = record.u32()

        attr_name = pool.get(attr_name_index)
        if not attr_name:
            # Name pool stripped: fall back to the attribute's resource ID.
            if 0 <= attr_name_index < len(resource_map):
                attr_name = ATTR_RESOURCE_IDS.get(
                    resource_map[attr_name_index],
                    f"attr_0x{resource_map[attr_name_index]:08x}",
                )
            else:
                attr_name = f"attr_{attr_name_index}"

        namespace = pool.get(ns_index)
        if namespace == _ANDROID_NS:
            attr_name = f"android:{attr_name}"

        element.attributes[attr_name] = _format_value(
            pool, raw_value_index, data_type, value_data
        )

    return element


def _format_value(
    pool: StringPool, raw_index: int, data_type: int, value: int
) -> str:
    if data_type == TYPE_STRING:
        text = pool.get(value)
        return text if text else pool.get(raw_index)
    if data_type == TYPE_INT_BOOLEAN:
        return "true" if value != 0 else "false"
    if data_type == TYPE_INT_HEX:
        return f"0x{value:08x}"
    if data_type == TYPE_INT_DEC:
        # Values above 2^31 are stored unsigned; present them the way aapt would.
        return str(value if value < 0x80000000 else value - 0x100000000)
    if data_type == TYPE_REFERENCE:
        return f"@0x{value:08x}"
    if data_type == TYPE_ATTRIBUTE:
        return f"?0x{value:08x}"
    if data_type == TYPE_FLOAT:
        import struct as _struct

        return str(_struct.unpack("<f", _struct.pack("<I", value))[0])
    if data_type == TYPE_NULL:
        return ""
    raw = pool.get(raw_index)
    return raw if raw else str(value)
