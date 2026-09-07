"""resources.arsc reader.

In a built APK there is no `res/values/strings.xml` on disk — string resources are
compiled into `resources.arsc`. Its global string pool holds every resource string
value, which is a routine hiding place for API keys and backend URLs, so the tool
reads it directly rather than requiring apktool.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from masa.decompile.binio import ParseError, Reader
from masa.decompile.stringpool import (
    RES_STRING_POOL_TYPE,
    StringPool,
    parse_string_pool,
)

RES_TABLE_TYPE = 0x0002
RES_TABLE_PACKAGE_TYPE = 0x0200
RES_TABLE_TYPE_TYPE = 0x0201
RES_TABLE_TYPE_SPEC_TYPE = 0x0202

_FLAG_COMPLEX = 0x0001
_TYPE_STRING = 0x03
_NO_ENTRY = 0xFFFFFFFF
_MAX_ENTRIES = 200_000


@dataclass
class ResourceString:
    """One resolved string resource: its name, its value and its type."""

    name: str
    value: str
    type_name: str = "string"

    @property
    def location(self) -> str:
        return f"res/values/{self.type_name}s.xml:{self.name}"


@dataclass
class ResourceTable:
    values: list[str] = field(default_factory=list)
    """Every string in the table's global value pool."""

    keys: list[str] = field(default_factory=list)
    """Resource entry names (`app_name`, `google_api_key`, ...) from package key pools."""

    strings: list[ResourceString] = field(default_factory=list)
    """Resolved name -> value pairs, produced by walking the type chunks."""

    package_names: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def looks_like_arsc(data: bytes) -> bool:
    return len(data) >= 8 and data[0] == 0x02 and data[1] == 0x00


def parse_arsc(data: bytes) -> ResourceTable:
    """Extract the string and key pools from a resource table."""
    table = ResourceTable()
    if len(data) < 12:
        raise ParseError("resources.arsc too small to contain a table header")

    reader = Reader(data)
    chunk_type = reader.u16()
    header_size = reader.u16()
    chunk_size = reader.u32()
    if chunk_type != RES_TABLE_TYPE:
        raise ParseError(f"not a resource table (chunk type 0x{chunk_type:04x})")
    package_count = reader.u32()
    end = min(chunk_size, len(data)) if chunk_size >= 12 else len(data)
    if chunk_size > len(data):
        table.warnings.append(
            f"table declares {chunk_size} bytes but file has {len(data)}; parsed partially"
        )
    if package_count > 4096:
        raise ParseError(f"table declares {package_count} packages")

    offset = max(header_size, 12)
    while offset + 8 <= end:
        sub = Reader(data, offset)
        sub_type = sub.u16()
        sub_header = sub.u16()
        sub_size = sub.u32()
        if sub_size < 8 or offset + sub_size > end:
            table.warnings.append(f"chunk 0x{sub_type:04x} at {offset} has a bad size")
            break

        try:
            if sub_type == RES_STRING_POOL_TYPE and not table.values:
                pool, _ = parse_string_pool(data, offset)
                table.values = pool.as_list()
            elif sub_type == RES_TABLE_PACKAGE_TYPE:
                _parse_package(data, offset, sub_header, sub_size, table)
        except ParseError as exc:
            table.warnings.append(f"chunk 0x{sub_type:04x} at {offset}: {exc}")

        offset += sub_size

    return table


def _parse_package(
    data: bytes, offset: int, header_size: int, chunk_size: int, table: ResourceTable
) -> None:
    reader = Reader(data, offset + 8)
    reader.u32()  # package id
    # 128 UTF-16 code units of package name, NUL padded.
    raw_name = reader.bytes(256)
    name = raw_name.decode("utf-16-le", "replace").split("\x00", 1)[0]
    if name:
        table.package_names.append(name)

    type_strings_off = reader.u32()
    reader.u32()  # last public type
    key_strings_off = reader.u32()

    type_pool = StringPool([], False)
    key_pool = StringPool([], False)
    for pool_off, target in ((type_strings_off, "type"), (key_strings_off, "key")):
        if not pool_off:
            continue
        absolute = offset + pool_off
        if absolute + 8 > offset + chunk_size:
            continue
        try:
            pool, _ = parse_string_pool(data, absolute)
        except ParseError:
            continue
        if target == "key":
            key_pool = pool
            table.keys.extend(pool.as_list())
        else:
            type_pool = pool

    # Walk the package's sub-chunks for typed entry tables, which is what actually
    # pairs a resource name with its value.
    inner = offset + max(header_size, 288)
    end = offset + chunk_size
    while inner + 8 <= end:
        sub = Reader(data, inner)
        sub_type = sub.u16()
        sub_header = sub.u16()
        sub_size = sub.u32()
        if sub_size < 8 or inner + sub_size > end:
            break
        if sub_type == RES_TABLE_TYPE_TYPE:
            try:
                _parse_type_chunk(
                    data, inner, sub_header, sub_size, type_pool, key_pool, table
                )
            except ParseError as exc:
                table.warnings.append(f"type chunk at {inner}: {exc}")
        inner += sub_size


def _parse_type_chunk(
    data: bytes,
    offset: int,
    header_size: int,
    chunk_size: int,
    type_pool: StringPool,
    key_pool: StringPool,
    table: ResourceTable,
) -> None:
    """Resolve one ResTable_type chunk into name/value pairs."""
    reader = Reader(data, offset + 8)
    type_id = reader.u8()
    reader.u8()  # res0
    reader.u16()  # res1
    entry_count = reader.u32()
    entries_start = reader.u32()

    if entry_count > _MAX_ENTRIES:
        raise ParseError(f"type chunk declares {entry_count} entries")
    type_name = type_pool.get(type_id - 1) or "string"
    # Only string-valued types can carry a secret worth reporting.
    if type_name not in ("string", "array"):
        return

    offsets_base = offset + header_size
    data_base = offset + entries_start
    end = offset + chunk_size
    if offsets_base + 4 * entry_count > end:
        raise ParseError("entry offset table overruns the chunk")

    seen: set[tuple[str, str]] = {(s.name, s.value) for s in table.strings}
    index_reader = Reader(data)
    for index in range(entry_count):
        entry_offset = index_reader.u32_at(offsets_base + 4 * index)
        if entry_offset == _NO_ENTRY:
            continue
        start = data_base + entry_offset
        if start + 8 > end:
            continue
        entry = Reader(data, start)
        entry.u16()  # entry size
        flags = entry.u16()
        key_index = entry.u32()
        if flags & _FLAG_COMPLEX:
            continue  # a map entry (style/array), not a plain value
        if entry.pos + 8 > end:
            continue
        entry.u16()  # value size
        entry.u8()  # res0
        value_type = entry.u8()
        value_data = entry.u32()
        if value_type != _TYPE_STRING:
            continue
        name = key_pool.get(key_index)
        value = table.values[value_data] if value_data < len(table.values) else ""
        if not value:
            continue
        pair = (name, value)
        if pair in seen:
            continue
        seen.add(pair)
        table.strings.append(
            ResourceString(name=name, value=value, type_name=type_name)
        )
