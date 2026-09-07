"""Mach-O reader for iOS main binaries.

`otool` and `class-dump` are macOS-only and often absent, so the facts that
matter for static analysis are read directly from the file: the FairPlay
encryption flag, PIE and other hardening bits, linked dylibs, whether symbols
were stripped, and the Objective-C class and selector name tables — which is
most of what `class-dump` is used for in a security review.

Fat (universal) binaries are handled by picking the first architecture slice.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from masa.decompile.binio import ParseError, Reader

MH_MAGIC = 0xFEEDFACE
MH_MAGIC_64 = 0xFEEDFACF
MH_CIGAM = 0xCEFAEDFE
MH_CIGAM_64 = 0xCFFAEDFE
FAT_MAGIC = 0xCAFEBABE
FAT_CIGAM = 0xBEBAFECA

# Header flags.
MH_PIE = 0x00200000
MH_ALLOW_STACK_EXECUTION = 0x00020000
MH_NO_HEAP_EXECUTION = 0x01000000

LC_SEGMENT = 0x01
LC_SYMTAB = 0x02
LC_LOAD_DYLIB = 0x0C
LC_ID_DYLIB = 0x0D
LC_LOAD_WEAK_DYLIB = 0x80000018
LC_CODE_SIGNATURE = 0x1D
LC_SEGMENT_64 = 0x19
LC_ENCRYPTION_INFO = 0x21
LC_ENCRYPTION_INFO_64 = 0x2C
LC_RPATH = 0x8000001C

_CPU_NAMES = {
    7: "i386", 0x01000007: "x86_64",
    12: "arm", 0x0100000C: "arm64", 0x0200000C: "arm64_32",
}

_MAX_COMMANDS = 4096
_MAX_NAMES = 100_000


@dataclass
class MachOInfo:
    is_64bit: bool = False
    cpu_type: str = ""
    file_type: int = 0
    flags: int = 0
    encrypted: bool = False
    crypt_id: int = 0
    has_pie: bool = False
    stack_execution_allowed: bool = False
    has_code_signature: bool = False
    symbols_stripped: bool = True
    symbol_count: int = 0
    dylibs: list[str] = field(default_factory=list)
    rpaths: list[str] = field(default_factory=list)
    segments: list[str] = field(default_factory=list)
    objc_classes: list[str] = field(default_factory=list)
    objc_methods: list[str] = field(default_factory=list)
    architectures: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, object]:
        return {
            "cpu_type": self.cpu_type,
            "is_64bit": self.is_64bit,
            "architectures": list(self.architectures),
            "encrypted": self.encrypted,
            "crypt_id": self.crypt_id,
            "pie": self.has_pie,
            "code_signature": self.has_code_signature,
            "symbols_stripped": self.symbols_stripped,
            "symbol_count": self.symbol_count,
            "linked_libraries": list(self.dylibs),
            "objc_class_count": len(self.objc_classes),
        }


def looks_like_macho(data: bytes) -> bool:
    if len(data) < 4:
        return False
    magic = struct.unpack_from(">I", data, 0)[0]
    return magic in (MH_MAGIC, MH_MAGIC_64, MH_CIGAM, MH_CIGAM_64, FAT_MAGIC, FAT_CIGAM)


def parse_macho(data: bytes) -> MachOInfo:
    """Parse a Mach-O (or the first slice of a fat binary)."""
    if len(data) < 28:
        raise ParseError("buffer too small for a Mach-O header")

    big_magic = struct.unpack_from(">I", data, 0)[0]
    info = MachOInfo()
    offset = 0

    if big_magic in (FAT_MAGIC, FAT_CIGAM):
        offset = _select_fat_slice(data, info)

    return _parse_slice(data, offset, info)


def _select_fat_slice(data: bytes, info: MachOInfo) -> int:
    """Record every architecture and return the offset of the first usable slice."""
    count = struct.unpack_from(">I", data, 4)[0]
    if count == 0 or count > 64:
        raise ParseError(f"fat binary declares {count} architectures")
    chosen: int | None = None
    for index in range(count):
        base = 8 + index * 20
        if base + 20 > len(data):
            break
        cpu_type, _sub, arch_offset, arch_size, _align = struct.unpack_from(
            ">iiIII", data, base
        )
        info.architectures.append(_CPU_NAMES.get(cpu_type & 0xFFFFFFFF, f"cpu_{cpu_type}"))
        if chosen is None and 0 < arch_offset < len(data) and arch_size > 0:
            chosen = arch_offset
    if chosen is None:
        raise ParseError("fat binary contains no usable architecture slice")
    return chosen


def _parse_slice(data: bytes, offset: int, info: MachOInfo) -> MachOInfo:
    reader = Reader(data, offset)
    magic = reader.u32()

    if magic in (MH_CIGAM, MH_CIGAM_64):
        raise ParseError(
            "big-endian Mach-O is not supported (no iOS device uses this byte order)"
        )
    if magic not in (MH_MAGIC, MH_MAGIC_64):
        raise ParseError(f"not a Mach-O binary (magic 0x{magic:08x})")

    info.is_64bit = magic == MH_MAGIC_64
    cpu_type = reader.u32()
    reader.u32()  # cpu subtype
    info.file_type = reader.u32()
    command_count = reader.u32()
    commands_size = reader.u32()
    info.flags = reader.u32()
    if info.is_64bit:
        reader.u32()  # reserved

    info.cpu_type = _CPU_NAMES.get(cpu_type, f"cpu_{cpu_type}")
    if not info.architectures:
        info.architectures.append(info.cpu_type)
    info.has_pie = bool(info.flags & MH_PIE)
    info.stack_execution_allowed = bool(info.flags & MH_ALLOW_STACK_EXECUTION)

    if command_count > _MAX_COMMANDS:
        raise ParseError(f"binary declares {command_count} load commands")

    position = reader.pos
    end = min(position + commands_size, len(data))
    sections: list[tuple[str, int, int]] = []

    for _ in range(command_count):
        if position + 8 > end:
            info.warnings.append("load commands truncated")
            break
        command, command_size = struct.unpack_from("<II", data, position)
        if command_size < 8 or position + command_size > end:
            info.warnings.append(f"load command 0x{command:x} has a bad size")
            break
        body = data[position : position + command_size]
        try:
            _handle_command(command, body, info, sections)
        except (ParseError, struct.error, IndexError):
            info.warnings.append(f"could not parse load command 0x{command:x}")
        position += command_size

    _read_objc_names(data, sections, info)
    return info


def _handle_command(
    command: int,
    body: bytes,
    info: MachOInfo,
    sections: list[tuple[str, int, int]],
) -> None:
    if command in (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_ID_DYLIB):
        name_offset = struct.unpack_from("<I", body, 8)[0]
        name = _cstring(body, name_offset)
        if name and command != LC_ID_DYLIB:
            info.dylibs.append(name)
    elif command == LC_RPATH:
        name_offset = struct.unpack_from("<I", body, 8)[0]
        path = _cstring(body, name_offset)
        if path:
            info.rpaths.append(path)
    elif command == LC_CODE_SIGNATURE:
        info.has_code_signature = True
    elif command == LC_SYMTAB:
        # symtab_command: cmd, cmdsize, symoff, nsyms, stroff, strsize
        _symoff, nsyms = struct.unpack_from("<II", body, 8)
        info.symbol_count = nsyms
        # A release build stripped of local symbols keeps only a handful of
        # exported ones; several thousand means the symbol table is intact.
        info.symbols_stripped = nsyms < 200
    elif command in (LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64):
        _off, _size, crypt_id = struct.unpack_from("<III", body, 8)
        info.crypt_id = crypt_id
        info.encrypted = crypt_id != 0
    elif command in (LC_SEGMENT, LC_SEGMENT_64):
        _read_segment(command, body, info, sections)


def _read_segment(
    command: int,
    body: bytes,
    info: MachOInfo,
    sections: list[tuple[str, int, int]],
) -> None:
    is_64 = command == LC_SEGMENT_64
    seg_name = body[8:24].split(b"\x00", 1)[0].decode("ascii", "replace")
    info.segments.append(seg_name)

    if is_64:
        section_count = struct.unpack_from("<I", body, 64)[0]
        header_size, section_size = 72, 80
    else:
        section_count = struct.unpack_from("<I", body, 48)[0]
        header_size, section_size = 56, 68

    if section_count > 512:
        return
    for index in range(section_count):
        base = header_size + index * section_size
        if base + section_size > len(body):
            break
        name = body[base : base + 16].split(b"\x00", 1)[0].decode("ascii", "replace")
        if is_64:
            _addr, size = struct.unpack_from("<QQ", body, base + 32)
            file_offset = struct.unpack_from("<I", body, base + 48)[0]
        else:
            _addr, size = struct.unpack_from("<II", body, base + 32)
            file_offset = struct.unpack_from("<I", body, base + 40)[0]
        sections.append((name, file_offset, size))


def _read_objc_names(
    data: bytes, sections: list[tuple[str, int, int]], info: MachOInfo
) -> None:
    """Recover Objective-C class and selector names from the __TEXT string tables.

    These sections are plain NUL-separated C strings, which is why a full
    class-dump is not needed to enumerate the app's own class and method names.
    """
    for name, offset, size in sections:
        if name not in ("__objc_classname", "__objc_methname"):
            continue
        if offset <= 0 or size <= 0 or offset + size > len(data):
            continue
        blob = data[offset : offset + size]
        values = [
            part.decode("utf-8", "replace")
            for part in blob.split(b"\x00")
            if part and len(part) < 512
        ][:_MAX_NAMES]
        if name == "__objc_classname":
            info.objc_classes.extend(values)
        else:
            info.objc_methods.extend(values)


def _cstring(body: bytes, offset: int) -> str:
    if offset < 0 or offset >= len(body):
        return ""
    end = body.find(b"\x00", offset)
    raw = body[offset:] if end < 0 else body[offset:end]
    return raw.decode("utf-8", "replace")
