"""Android binary resource string pool (RES_STRING_POOL_TYPE).

Shared by AndroidManifest.xml (AXML) and resources.arsc — both embed the same
chunk. Parsing it is what lets this tool read a compiled manifest and the app's
string resources without apktool.
"""

from __future__ import annotations

from masa.decompile.binio import ParseError, Reader

RES_STRING_POOL_TYPE = 0x0001

_SORTED_FLAG = 1 << 0
_UTF8_FLAG = 1 << 8

# A single resource string longer than this is a corrupt or hostile length field.
_MAX_STRING_CHARS = 1 << 20
_MAX_STRINGS = 500_000


class StringPool:
    """Lazily decoded pool; `get(i)` returns '' for any out-of-range index."""

    def __init__(self, strings: list[str], is_utf8: bool) -> None:
        self._strings = strings
        self.is_utf8 = is_utf8

    def __len__(self) -> int:
        return len(self._strings)

    def __iter__(self):
        return iter(self._strings)

    def get(self, index: int) -> str:
        # 0xFFFFFFFF is the format's "no string" sentinel and shows up constantly
        # in real manifests, so an unknown index is normal, not an error.
        if index < 0 or index >= len(self._strings):
            return ""
        return self._strings[index]

    def as_list(self) -> list[str]:
        return list(self._strings)


def _decode_length_utf16(reader: Reader) -> int:
    length = reader.u16()
    if length & 0x8000:
        length = ((length & 0x7FFF) << 16) | reader.u16()
    return length


def _decode_length_utf8(reader: Reader) -> int:
    length = reader.u8()
    if length & 0x80:
        length = ((length & 0x7F) << 8) | reader.u8()
    return length


def parse_string_pool(data: bytes, offset: int) -> tuple[StringPool, int]:
    """Parse the pool chunk starting at `offset`. Returns (pool, chunk_size)."""
    reader = Reader(data, offset)
    chunk_type = reader.u16()
    if chunk_type != RES_STRING_POOL_TYPE:
        raise ParseError(f"expected string pool chunk, got type 0x{chunk_type:04x}")
    header_size = reader.u16()
    chunk_size = reader.u32()
    if chunk_size < 8 or offset + chunk_size > len(data):
        raise ParseError(
            f"string pool declares {chunk_size} bytes at {offset}, buffer has "
            f"{len(data) - offset}"
        )
    if header_size < 28 or header_size > chunk_size:
        raise ParseError(f"implausible string pool header size {header_size}")

    string_count = reader.u32()
    style_count = reader.u32()
    flags = reader.u32()
    strings_start = reader.u32()
    _styles_start = reader.u32()

    if string_count > _MAX_STRINGS:
        raise ParseError(f"string pool declares {string_count} strings")
    is_utf8 = bool(flags & _UTF8_FLAG)

    # Offsets array sits immediately after the header.
    offsets_base = offset + header_size
    if offsets_base + 4 * string_count > offset + chunk_size:
        raise ParseError("string pool offset table overruns the chunk")

    data_base = offset + strings_start
    if string_count and (strings_start < header_size or data_base > offset + chunk_size):
        raise ParseError(f"string data start {strings_start} outside pool chunk")

    chunk_end = offset + chunk_size
    strings: list[str] = []
    for index in range(string_count):
        entry_offset = Reader(data).u32_at(offsets_base + 4 * index)
        start = data_base + entry_offset
        if start < data_base or start >= chunk_end:
            strings.append("")
            continue
        try:
            strings.append(_read_string(data, start, chunk_end, is_utf8))
        except ParseError:
            # One corrupt entry should not lose the other few thousand.
            strings.append("")

    _ = style_count  # styles carry formatting spans only; nothing security-relevant
    return StringPool(strings, is_utf8), chunk_size


def _read_string(data: bytes, start: int, limit: int, is_utf8: bool) -> str:
    reader = Reader(data[:limit], start)
    if is_utf8:
        _decode_length_utf8(reader)  # length in UTF-16 code units, unused
        byte_length = _decode_length_utf8(reader)
        if byte_length > _MAX_STRING_CHARS:
            raise ParseError(f"string of {byte_length} bytes exceeds cap")
        raw = reader.bytes(byte_length)
        return raw.decode("utf-8", "replace")

    char_length = _decode_length_utf16(reader)
    if char_length > _MAX_STRING_CHARS:
        raise ParseError(f"string of {char_length} chars exceeds cap")
    raw = reader.bytes(char_length * 2)
    return raw.decode("utf-16-le", "replace")
