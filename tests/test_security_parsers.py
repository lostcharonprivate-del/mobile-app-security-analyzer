"""Security tests for the binary parsers.

Every parser in this tool reads attacker-controlled bytes. The contract each one
must honour is: for *any* input, terminate quickly, raise only a ParseError (or
return a partial result), and never allocate unbounded memory. These tests attack
each parser three ways — targeted malformation of the length and count fields
that drive allocation and looping, systematic truncation, and random bit flips
across the real fixture files.
"""

from __future__ import annotations

import os
import random
import struct
import time
import zipfile
from pathlib import Path

import pytest

from masa.decompile.arsc import parse_arsc
from masa.decompile.axml import parse_axml
from masa.decompile.binio import ParseError, Reader
from masa.decompile.dex import parse_dex
from masa.decompile.macho import parse_macho
from masa.errors import DecompileError

# Any single parse must finish well inside this. A parser that hangs on hostile
# input is a denial-of-service in a tool whose whole job is reading hostile input.
PARSE_BUDGET_SECONDS = 10.0


def _parse_within_budget(parser, data: bytes, label: str):
    """Run a parser, allowing only ParseError/DecompileError, and time it."""
    started = time.monotonic()
    try:
        result = parser(data)
    except (ParseError, DecompileError):
        result = None
    except (MemoryError, RecursionError) as exc:  # pragma: no cover - a real failure
        pytest.fail(f"{label}: parser exhausted a resource: {type(exc).__name__}")
    except Exception as exc:  # noqa: BLE001 - any other exception is a contract break
        pytest.fail(f"{label}: unexpected {type(exc).__name__}: {exc}")
    elapsed = time.monotonic() - started
    assert elapsed < PARSE_BUDGET_SECONDS, f"{label}: parse took {elapsed:.1f}s"
    return result


# -- bounds-checked reader ----------------------------------------------------


class TestReader:
    def test_reads_past_the_end_are_refused(self):
        reader = Reader(b"\x01\x02")
        with pytest.raises(ParseError):
            reader.u32()

    def test_negative_and_out_of_range_seeks_are_refused(self):
        reader = Reader(b"abcd")
        for target in (-1, 5, 1 << 40):
            with pytest.raises(ParseError):
                reader.seek(target)

    def test_negative_read_length_is_refused(self):
        with pytest.raises(ParseError):
            Reader(b"abcd").bytes(-1)

    def test_uleb128_cannot_run_away(self):
        # A continuation bit on every byte would loop forever without the cap.
        reader = Reader(b"\xff" * 64)
        with pytest.raises(ParseError):
            reader.uleb128()

    def test_u32_at_bounds_are_checked(self):
        reader = Reader(b"abcd")
        with pytest.raises(ParseError):
            reader.u32_at(2)


# -- AXML ---------------------------------------------------------------------


class TestAxmlRobustness:
    @staticmethod
    @pytest.fixture(scope="class")
    def manifest(apk_path: Path) -> bytes:
        with zipfile.ZipFile(apk_path) as archive:
            return archive.read("AndroidManifest.xml")

    def test_valid_manifest_parses(self, manifest: bytes):
        document = parse_axml(manifest)
        assert document.root is not None
        assert document.root.name == "manifest"

    @pytest.mark.parametrize("cut", [0, 1, 7, 8, 16, 64, 256, 1024, 4096])
    def test_truncation_never_crashes(self, manifest: bytes, cut: int):
        _parse_within_budget(parse_axml, manifest[:cut], f"axml truncated to {cut}")

    def test_oversized_chunk_size_is_bounded(self, manifest: bytes):
        data = bytearray(manifest)
        struct.pack_into("<I", data, 4, 0xFFFFFFFF)  # chunk size
        document = _parse_within_budget(parse_axml, bytes(data), "axml huge chunk size")
        if document is not None:
            assert any("parsed partially" in w for w in document.warnings)

    def test_zero_chunk_size_does_not_loop(self, manifest: bytes):
        """A sub-chunk claiming zero length would spin forever without a floor."""
        data = bytearray(manifest)
        struct.pack_into("<I", data, 12, 0)  # first sub-chunk's size field
        _parse_within_budget(parse_axml, bytes(data), "axml zero sub-chunk")

    def test_huge_string_count_is_refused(self, manifest: bytes):
        data = bytearray(manifest)
        struct.pack_into("<I", data, 16, 0xFFFFFFF0)  # string pool stringCount
        _parse_within_budget(parse_axml, bytes(data), "axml huge string count")

    def test_random_bit_flips(self, manifest: bytes):
        rng = random.Random(20240607)
        for iteration in range(250):
            data = bytearray(manifest)
            for _ in range(rng.randint(1, 12)):
                index = rng.randrange(len(data))
                data[index] ^= 1 << rng.randrange(8)
            _parse_within_budget(parse_axml, bytes(data), f"axml fuzz {iteration}")

    def test_non_axml_input_raises_parse_error(self):
        with pytest.raises(ParseError):
            parse_axml(b"not an axml document at all")


# -- DEX ----------------------------------------------------------------------


class TestDexRobustness:
    @staticmethod
    @pytest.fixture(scope="class")
    def dex(apk_path: Path) -> bytes:
        with zipfile.ZipFile(apk_path) as archive:
            return archive.read("classes.dex")

    def test_valid_dex_parses(self, dex: bytes):
        parsed = parse_dex(dex)
        assert parsed.classes and parsed.strings

    @pytest.mark.parametrize("cut", [0, 8, 64, 112, 200, 1024, 8192])
    def test_truncation_never_crashes(self, dex: bytes, cut: int):
        _parse_within_budget(parse_dex, dex[:cut], f"dex truncated to {cut}")

    @pytest.mark.parametrize(
        "offset,label",
        [
            (56, "string_ids_size"), (60, "string_ids_off"),
            (64, "type_ids_size"), (68, "type_ids_off"),
            (80, "field_ids_size"), (88, "method_ids_size"),
            (96, "class_defs_size"), (100, "class_defs_off"),
        ],
    )
    def test_absurd_table_sizes_are_refused(self, dex: bytes, offset: int, label: str):
        data = bytearray(dex)
        struct.pack_into("<I", data, offset, 0xFFFFFFF0)
        _parse_within_budget(parse_dex, bytes(data), f"dex huge {label}")

    def test_bad_magic_is_refused(self, dex: bytes):
        with pytest.raises(ParseError, match="magic"):
            parse_dex(b"xxx\n035\x00" + dex[8:])

    def test_wrong_endianness_tag_is_refused(self, dex: bytes):
        data = bytearray(dex)
        struct.pack_into("<I", data, 40, 0x78563412)
        with pytest.raises(ParseError, match="endian"):
            parse_dex(bytes(data))

    def test_declared_file_size_larger_than_buffer_is_noted(self, dex: bytes):
        data = bytearray(dex)
        struct.pack_into("<I", data, 32, 0x7FFFFFFF)
        parsed = _parse_within_budget(parse_dex, bytes(data), "dex oversized file_size")
        if parsed is not None:
            assert any("parsed partially" in w for w in parsed.warnings)

    def test_random_bit_flips(self, dex: bytes):
        rng = random.Random(987654321)
        for iteration in range(250):
            data = bytearray(dex)
            for _ in range(rng.randint(1, 16)):
                index = rng.randrange(len(data))
                data[index] ^= 1 << rng.randrange(8)
            _parse_within_budget(parse_dex, bytes(data), f"dex fuzz {iteration}")

    def test_code_walk_terminates_on_hostile_bytecode(self, dex: bytes):
        """Corrupting only the code section must not produce a non-terminating walk."""
        rng = random.Random(13579)
        for iteration in range(120):
            data = bytearray(dex)
            # The data section sits after the fixed tables; scribble there.
            start = min(len(data) - 1, 0x200)
            for _ in range(rng.randint(4, 40)):
                data[rng.randrange(start, len(data))] = rng.randrange(256)
            _parse_within_budget(parse_dex, bytes(data), f"dex code fuzz {iteration}")


# -- resources.arsc -----------------------------------------------------------


class TestArscRobustness:
    @staticmethod
    @pytest.fixture(scope="class")
    def arsc(apk_path: Path) -> bytes:
        with zipfile.ZipFile(apk_path) as archive:
            return archive.read("resources.arsc")

    def test_valid_table_parses(self, arsc: bytes):
        table = parse_arsc(arsc)
        assert table.package_names
        assert table.strings

    @pytest.mark.parametrize("cut", [0, 8, 12, 64, 256, 512])
    def test_truncation_never_crashes(self, arsc: bytes, cut: int):
        _parse_within_budget(parse_arsc, arsc[:cut], f"arsc truncated to {cut}")

    def test_absurd_package_count_is_refused(self, arsc: bytes):
        data = bytearray(arsc)
        struct.pack_into("<I", data, 8, 0xFFFFFFF0)
        _parse_within_budget(parse_arsc, bytes(data), "arsc huge package count")

    def test_random_bit_flips(self, arsc: bytes):
        rng = random.Random(1122334455)
        for iteration in range(250):
            data = bytearray(arsc)
            for _ in range(rng.randint(1, 10)):
                index = rng.randrange(len(data))
                data[index] ^= 1 << rng.randrange(8)
            _parse_within_budget(parse_arsc, bytes(data), f"arsc fuzz {iteration}")


# -- Mach-O -------------------------------------------------------------------


class TestMachORobustness:
    @staticmethod
    @pytest.fixture(scope="class")
    def macho(ipa_path: Path) -> bytes:
        with zipfile.ZipFile(ipa_path) as archive:
            name = next(
                n for n in archive.namelist()
                if n.endswith("/VulnerableDemo") or n.endswith(".app/VulnerableDemo")
            )
            return archive.read(name)

    def test_valid_binary_parses(self, macho: bytes):
        info = parse_macho(macho)
        assert info.cpu_type
        assert info.dylibs

    @pytest.mark.parametrize("cut", [0, 4, 27, 28, 64, 512, 2048])
    def test_truncation_never_crashes(self, macho: bytes, cut: int):
        _parse_within_budget(parse_macho, macho[:cut], f"macho truncated to {cut}")

    def test_absurd_load_command_count_is_refused(self, macho: bytes):
        data = bytearray(macho)
        struct.pack_into("<I", data, 16, 0xFFFFFFF0)  # ncmds
        _parse_within_budget(parse_macho, bytes(data), "macho huge ncmds")

    def test_zero_sized_load_command_does_not_loop(self, macho: bytes):
        data = bytearray(macho)
        struct.pack_into("<I", data, 36, 0)  # first load command's cmdsize
        _parse_within_budget(parse_macho, bytes(data), "macho zero cmdsize")

    def test_fat_header_with_absurd_arch_count_is_refused(self):
        data = struct.pack(">II", 0xCAFEBABE, 0xFFFFFFF0) + b"\x00" * 128
        _parse_within_budget(parse_macho, data, "fat huge arch count")

    def test_fat_slice_offset_outside_the_file_is_refused(self):
        header = struct.pack(">II", 0xCAFEBABE, 1)
        arch = struct.pack(">iiIII", 0x0100000C, 0, 0xFFFFFF00, 1024, 14)
        _parse_within_budget(parse_macho, header + arch + b"\x00" * 64, "fat bad offset")

    def test_random_bit_flips(self, macho: bytes):
        rng = random.Random(24680)
        for iteration in range(250):
            data = bytearray(macho)
            for _ in range(rng.randint(1, 12)):
                index = rng.randrange(len(data))
                data[index] ^= 1 << rng.randrange(8)
            _parse_within_budget(parse_macho, bytes(data), f"macho fuzz {iteration}")

    def test_non_macho_input_is_refused(self):
        with pytest.raises(ParseError):
            parse_macho(b"PK\x03\x04" + b"\x00" * 128)


# -- random input across every parser ----------------------------------------


class TestRandomInput:
    @pytest.mark.parametrize(
        "parser,label",
        [(parse_axml, "axml"), (parse_dex, "dex"), (parse_arsc, "arsc"), (parse_macho, "macho")],
    )
    def test_pure_random_bytes(self, parser, label: str):
        rng = random.Random(hash(label) & 0xFFFF)
        for iteration in range(150):
            size = rng.choice([0, 1, 7, 15, 64, 300, 5000])
            data = bytes(rng.randrange(256) for _ in range(size))
            _parse_within_budget(parser, data, f"{label} random {iteration}")

    @pytest.mark.parametrize(
        "parser,magic,label",
        [
            (parse_axml, b"\x03\x00\x08\x00", "axml"),
            (parse_dex, b"dex\n035\x00", "dex"),
            (parse_arsc, b"\x02\x00\x0c\x00", "arsc"),
            (parse_macho, struct.pack("<I", 0xFEEDFACF), "macho"),
        ],
    )
    def test_valid_magic_then_random_bytes(self, parser, magic: bytes, label: str):
        """The nastiest shape: a header good enough to get past the sniff."""
        rng = random.Random(0xC0FFEE ^ len(label))
        for iteration in range(150):
            body = bytes(rng.randrange(256) for _ in range(rng.randrange(16, 2048)))
            _parse_within_budget(parser, magic + body, f"{label} magic+random {iteration}")
