"""Bounds-checked little-endian reader.

Every byte parsed by this tool comes from an untrusted file, so all structured
parsing goes through this reader: it can never read past the buffer, and a
malformed length turns into a clean exception instead of a huge allocation or a
runaway loop.
"""

from __future__ import annotations

import struct

from masa.errors import DecompileError


class ParseError(DecompileError):
    """The binary structure is malformed or truncated."""


class Reader:
    __slots__ = ("data", "pos", "_len")

    def __init__(self, data: bytes, pos: int = 0) -> None:
        self.data = data
        self._len = len(data)
        self.pos = pos

    def __len__(self) -> int:
        return self._len

    @property
    def remaining(self) -> int:
        return max(0, self._len - self.pos)

    def seek(self, pos: int) -> None:
        if pos < 0 or pos > self._len:
            raise ParseError(f"seek to {pos} outside buffer of {self._len} bytes")
        self.pos = pos

    def require(self, count: int) -> None:
        if count < 0:
            raise ParseError(f"negative read length {count}")
        if self.pos + count > self._len:
            raise ParseError(
                f"read of {count} bytes at {self.pos} exceeds buffer of {self._len}"
            )

    def bytes(self, count: int) -> bytes:
        self.require(count)
        out = self.data[self.pos : self.pos + count]
        self.pos += count
        return out

    def u8(self) -> int:
        self.require(1)
        value = self.data[self.pos]
        self.pos += 1
        return value

    def u16(self) -> int:
        self.require(2)
        value = struct.unpack_from("<H", self.data, self.pos)[0]
        self.pos += 2
        return value

    def u32(self) -> int:
        self.require(4)
        value = struct.unpack_from("<I", self.data, self.pos)[0]
        self.pos += 4
        return value

    def i32(self) -> int:
        self.require(4)
        value = struct.unpack_from("<i", self.data, self.pos)[0]
        self.pos += 4
        return value

    def u32_at(self, offset: int) -> int:
        if offset < 0 or offset + 4 > self._len:
            raise ParseError(f"u32 read at {offset} outside buffer of {self._len}")
        return struct.unpack_from("<I", self.data, offset)[0]

    def uleb128(self) -> int:
        """DEX-style unsigned LEB128, capped at 5 bytes as the format requires."""
        result = 0
        for shift in range(0, 35, 7):
            byte = self.u8()
            result |= (byte & 0x7F) << shift
            if not byte & 0x80:
                return result
        raise ParseError("ULEB128 value longer than 5 bytes")
