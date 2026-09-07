"""DEX (Dalvik executable) parser — the pure-Python route to Android bytecode.

jadx gives prettier output, but it is a 100MB Java dependency. Everything this
tool actually needs for static analysis is recoverable straight from the DEX:

* the full string pool (every literal the app can produce);
* type, field and method references (which platform APIs the app touches);
* per-class method bodies, walked at the instruction level so that a dangerous
  call or a hardcoded string can be attributed to `com.example.Foo.bar()` rather
  than to "somewhere in classes.dex".

Everything is bounds-checked: a hostile DEX gets a partial parse and a warning,
never an unbounded allocation or a non-terminating loop.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from masa.decompile.binio import ParseError, Reader

DEX_MAGICS = {
    b"dex\n035\x00",
    b"dex\n037\x00",
    b"dex\n038\x00",
    b"dex\n039\x00",
    b"dex\n040\x00",
    b"dex\n041\x00",
}
_ENDIAN_TAG = 0x12345678
_HEADER_SIZE = 0x70

_MAX_ITEMS = 2_000_000
_MAX_STRING_BYTES = 1 << 20
_MAX_CALL_SITES_PER_TARGET = 64
_MAX_CODE_UNITS = 1 << 22

ACC_PUBLIC = 0x0001
ACC_STATIC = 0x0008
ACC_FINAL = 0x0010
ACC_INTERFACE = 0x0200
ACC_ABSTRACT = 0x0400

# encoded_value type codes (DEX spec table).
VALUE_BOOLEAN = 0x1F
VALUE_NULL = 0x1E
VALUE_STRING = 0x17
VALUE_ARRAY = 0x1C
VALUE_ANNOTATION = 0x1D

# Instruction width in 16-bit code units, indexed by opcode. Widths come from the
# Dalvik instruction-format table; unused opcodes are 1 so the walk still advances.
_WIDTHS = [1] * 256


def _set_widths() -> None:
    def assign(spec: dict[range | int, int]) -> None:
        for key, width in spec.items():
            if isinstance(key, int):
                _WIDTHS[key] = width
            else:
                for op in key:
                    _WIDTHS[op] = width

    assign(
        {
            range(0x00, 0x02): 1,
            0x02: 2,
            0x03: 3,
            0x04: 1,
            0x05: 2,
            0x06: 3,
            0x07: 1,
            0x08: 2,
            0x09: 3,
            range(0x0A, 0x13): 1,
            0x13: 2,
            0x14: 3,
            0x15: 2,
            0x16: 2,
            0x17: 3,
            0x18: 5,
            0x19: 2,
            0x1A: 2,
            0x1B: 3,
            0x1C: 2,
            0x1D: 1,
            0x1E: 1,
            0x1F: 2,
            0x20: 2,
            0x21: 1,
            0x22: 2,
            0x23: 2,
            0x24: 3,
            0x25: 3,
            0x26: 3,
            0x27: 1,
            0x28: 1,
            0x29: 2,
            0x2A: 3,
            0x2B: 3,
            0x2C: 3,
            range(0x2D, 0x32): 2,
            range(0x32, 0x3E): 2,
            range(0x3E, 0x44): 1,
            range(0x44, 0x52): 2,
            range(0x52, 0x60): 2,
            range(0x60, 0x6E): 2,
            range(0x6E, 0x73): 3,
            0x73: 1,
            range(0x74, 0x79): 3,
            range(0x79, 0x7B): 1,
            range(0x7B, 0x90): 1,
            range(0x90, 0xB0): 2,
            range(0xB0, 0xD0): 1,
            range(0xD0, 0xD8): 2,
            range(0xD8, 0xE3): 2,
            range(0xE3, 0xFA): 1,
            0xFA: 4,
            0xFB: 4,
            0xFC: 3,
            0xFD: 3,
            0xFE: 2,
            0xFF: 2,
        }
    )


_set_widths()

_INVOKE_35C = frozenset({0x6E, 0x6F, 0x70, 0x71, 0x72, 0xFC})
_INVOKE_3RC = frozenset({0x74, 0x75, 0x76, 0x77, 0x78, 0xFD})
_INVOKE_45CC = frozenset({0xFA, 0xFB})
_FIELD_OPS = frozenset(range(0x52, 0x6E))
_CONST_OPS = frozenset({0x12, 0x13, 0x14, 0x15})
_MOVE_RESULT_OPS = frozenset({0x0A, 0x0B, 0x0C, 0x0D})


@dataclass
class MethodRef:
    class_name: str
    name: str
    proto: str

    @property
    def signature(self) -> str:
        return f"{self.class_name}->{self.name}"

    @property
    def full(self) -> str:
        return f"{self.class_name}->{self.name}{self.proto}"


@dataclass
class FieldRef:
    class_name: str
    type_name: str
    name: str

    @property
    def signature(self) -> str:
        return f"{self.class_name}->{self.name}"


@dataclass
class DexMethod:
    name: str
    class_name: str
    proto: str
    access_flags: int = 0
    insn_count: int = 0
    """Size of the method body in 16-bit code units; 0 means abstract or native."""

    has_body: bool = False
    returns_const: int | None = None
    """Set when the body does nothing but return a constant (or return void).

    This is what identifies the classic `checkServerTrusted` that validates
    nothing and the `HostnameVerifier.verify` that always returns true.
    """

    @property
    def display(self) -> str:
        return f"{java_name(self.class_name)}.{self.name}"

    @property
    def is_empty(self) -> bool:
        """True for a body that immediately returns without doing anything."""
        return self.has_body and self.insn_count <= 1


@dataclass
class Invocation:
    """One call site, with any argument values that were constant at the call."""

    site: "CallSite"
    args: tuple[int | None, ...] = ()
    """Resolved integer arguments, positionally; None where not a known constant."""

    def arg(self, index: int) -> int | None:
        return self.args[index] if 0 <= index < len(self.args) else None


@dataclass
class DexClass:
    name: str
    """Java-style name, e.g. `com.example.Foo`."""

    descriptor: str
    """Raw DEX descriptor, e.g. `Lcom/example/Foo;`."""

    superclass: str | None = None
    source_file: str | None = None
    access_flags: int = 0
    interfaces: list[str] = field(default_factory=list)
    methods: list[DexMethod] = field(default_factory=list)
    static_field_names: list[str] = field(default_factory=list)


@dataclass
class CallSite:
    """Where a method reference or string constant is used."""

    class_name: str
    method_name: str
    source_file: str | None = None
    kind: str = "method"
    """'method' for a call site, 'field' for a static field initialiser."""

    @property
    def location(self) -> str:
        suffix = "()" if self.kind == "method" else ""
        base = f"{self.class_name}.{self.method_name}{suffix}"
        if self.source_file:
            return f"{base} [{self.source_file}]"
        return base


def java_name(descriptor: str) -> str:
    """`Lcom/example/Foo;` -> `com.example.Foo`; arrays and primitives pass through."""
    if descriptor.startswith("L") and descriptor.endswith(";"):
        return descriptor[1:-1].replace("/", ".")
    return descriptor


def decode_mutf8(raw: bytes) -> str:
    """Decode Modified UTF-8 as used by DEX string data."""
    # The only routine difference from UTF-8 that matters for text extraction is
    # the 0xC0 0x80 encoding of NUL; surrogate pairs decode acceptably with
    # 'replace' and never affect pattern matching.
    if b"\xc0\x80" in raw:
        raw = raw.replace(b"\xc0\x80", b"\x00")
    return raw.decode("utf-8", "replace")


@dataclass
class DexFile:
    """Parsed contents of one classes*.dex."""

    name: str = "classes.dex"
    version: str = ""
    strings: list[str] = field(default_factory=list)
    type_names: list[str] = field(default_factory=list)
    method_refs: list[MethodRef] = field(default_factory=list)
    field_refs: list[FieldRef] = field(default_factory=list)
    classes: list[DexClass] = field(default_factory=list)
    call_sites: dict[int, list[CallSite]] = field(default_factory=dict)
    """method_ref index -> where it is invoked."""

    string_sites: dict[int, list[CallSite]] = field(default_factory=dict)
    """string index -> where it appears as a const-string."""

    field_sites: dict[int, list[CallSite]] = field(default_factory=dict)
    invocations: dict[int, list[Invocation]] = field(default_factory=dict)
    """method_ref index -> call sites with resolved constant arguments."""

    warnings: list[str] = field(default_factory=list)

    def method_signatures(self) -> set[str]:
        return {ref.signature for ref in self.method_refs}

    def sites_for_method(self, signature: str) -> list[CallSite]:
        """Every call site of a `Lclass;->name` signature."""
        out: list[CallSite] = []
        for index, ref in enumerate(self.method_refs):
            if ref.signature == signature:
                out.extend(self.call_sites.get(index, ()))
        return out

    def sites_for_string(self, value: str) -> list[CallSite]:
        out: list[CallSite] = []
        for index, text in enumerate(self.strings):
            if text == value:
                out.extend(self.string_sites.get(index, ()))
        return out

    def invocations_of(self, signature: str) -> list[Invocation]:
        """Every invocation of a `Lclass;->name` signature, with argument values."""
        out: list[Invocation] = []
        for index, ref in enumerate(self.method_refs):
            if ref.signature == signature:
                out.extend(self.invocations.get(index, ()))
        return out

    def invocations_by_name(
        self, method_name: str, receivers: tuple[str, ...] = ()
    ) -> list[Invocation]:
        """Invocations of a method by name, regardless of the declaring class.

        A call to an inherited method is recorded against the subclass — an
        Activity calling `getSharedPreferences` shows up as
        `Lcom/example/MainActivity;->getSharedPreferences`, not as `Context`.
        Matching on the name catches both, with an optional receiver filter for
        names that are not distinctive on their own.
        """
        out: list[Invocation] = []
        for index, ref in enumerate(self.method_refs):
            if ref.name != method_name:
                continue
            if receivers and not any(r in ref.class_name for r in receivers):
                continue
            out.extend(self.invocations.get(index, ()))
        return out

    def sites_by_name(
        self, method_name: str, receivers: tuple[str, ...] = ()
    ) -> list[CallSite]:
        return [inv.site for inv in self.invocations_by_name(method_name, receivers)]

    def methods_of(self, class_name: str) -> list[DexMethod]:
        for entry in self.classes:
            if entry.name == class_name:
                return entry.methods
        return []

    def classes_implementing(self, interface: str) -> list[DexClass]:
        return [c for c in self.classes if interface in c.interfaces]


def looks_like_dex(data: bytes) -> bool:
    return len(data) >= 8 and data[:8] in DEX_MAGICS


def parse_dex(data: bytes, name: str = "classes.dex") -> DexFile:
    """Parse a DEX buffer. Returns a partial result plus warnings if damaged."""
    if len(data) < _HEADER_SIZE:
        raise ParseError(f"DEX buffer is {len(data)} bytes, header needs {_HEADER_SIZE}")
    magic = data[:8]
    if magic not in DEX_MAGICS:
        raise ParseError(f"bad DEX magic {magic!r}")

    dex = DexFile(name=name, version=magic[4:7].decode("ascii", "replace"))
    reader = Reader(data, 8)
    reader.u32()  # checksum: integrity of the file, not a security control
    reader.bytes(20)  # SHA-1 signature
    file_size = reader.u32()
    header_size = reader.u32()
    endian_tag = reader.u32()

    if endian_tag != _ENDIAN_TAG:
        raise ParseError(f"unsupported endianness tag 0x{endian_tag:08x}")
    if header_size != _HEADER_SIZE:
        dex.warnings.append(f"unusual header size {header_size}")
    if file_size > len(data):
        dex.warnings.append(
            f"DEX declares {file_size} bytes but buffer has {len(data)}; parsed partially"
        )

    reader.u32()  # link_size
    reader.u32()  # link_off
    reader.u32()  # map_off
    string_ids_size, string_ids_off = reader.u32(), reader.u32()
    type_ids_size, type_ids_off = reader.u32(), reader.u32()
    proto_ids_size, proto_ids_off = reader.u32(), reader.u32()
    field_ids_size, field_ids_off = reader.u32(), reader.u32()
    method_ids_size, method_ids_off = reader.u32(), reader.u32()
    class_defs_size, class_defs_off = reader.u32(), reader.u32()

    for label, count in (
        ("string_ids", string_ids_size),
        ("type_ids", type_ids_size),
        ("method_ids", method_ids_size),
        ("class_defs", class_defs_size),
    ):
        if count > _MAX_ITEMS:
            raise ParseError(f"{label} declares {count} entries, above the safety cap")

    dex.strings = _parse_strings(data, string_ids_off, string_ids_size, dex)
    dex.type_names = _parse_types(data, type_ids_off, type_ids_size, dex.strings, dex)
    protos = _parse_protos(
        data, proto_ids_off, proto_ids_size, dex.strings, dex.type_names, dex
    )
    dex.field_refs = _parse_fields(
        data, field_ids_off, field_ids_size, dex.strings, dex.type_names, dex
    )
    dex.method_refs = _parse_methods(
        data, method_ids_off, method_ids_size, dex.strings, dex.type_names, protos, dex
    )
    _parse_class_defs(data, class_defs_off, class_defs_size, dex)
    return dex


def _parse_strings(data: bytes, off: int, count: int, dex: DexFile) -> list[str]:
    if count == 0 or off == 0:
        return []
    strings: list[str] = []
    ids = Reader(data)
    for index in range(count):
        try:
            data_off = ids.u32_at(off + 4 * index)
            strings.append(_read_string_data(data, data_off))
        except ParseError:
            strings.append("")
    if not strings:
        dex.warnings.append("string pool could not be read")
    return strings


def _read_string_data(data: bytes, offset: int) -> str:
    reader = Reader(data, offset)
    utf16_units = reader.uleb128()
    if utf16_units > _MAX_STRING_BYTES:
        raise ParseError(f"string declares {utf16_units} units")
    start = reader.pos
    # Data is NUL-terminated; the declared length is in UTF-16 units, so the byte
    # length can be larger. Scan for the terminator with a hard cap.
    end = data.find(b"\x00", start, min(len(data), start + _MAX_STRING_BYTES + 4))
    if end < 0:
        raise ParseError("unterminated string data")
    return decode_mutf8(data[start:end])


def _parse_types(
    data: bytes, off: int, count: int, strings: list[str], dex: DexFile
) -> list[str]:
    if count == 0 or off == 0:
        return []
    reader = Reader(data)
    out: list[str] = []
    for index in range(count):
        try:
            string_idx = reader.u32_at(off + 4 * index)
            out.append(strings[string_idx] if string_idx < len(strings) else "")
        except ParseError:
            out.append("")
    return out


def _parse_protos(
    data: bytes,
    off: int,
    count: int,
    strings: list[str],
    types: list[str],
    dex: DexFile,
) -> list[str]:
    if count == 0 or off == 0:
        return []
    reader = Reader(data)
    out: list[str] = []
    for index in range(count):
        try:
            base = off + 12 * index
            shorty_idx = reader.u32_at(base)
            out.append(strings[shorty_idx] if shorty_idx < len(strings) else "")
        except ParseError:
            out.append("")
    return out


def _parse_fields(
    data: bytes,
    off: int,
    count: int,
    strings: list[str],
    types: list[str],
    dex: DexFile,
) -> list[FieldRef]:
    if count == 0 or off == 0:
        return []
    out: list[FieldRef] = []
    reader = Reader(data, off)
    for _ in range(count):
        try:
            class_idx = reader.u16()
            type_idx = reader.u16()
            name_idx = reader.u32()
        except ParseError:
            dex.warnings.append("field_ids table truncated")
            break
        out.append(
            FieldRef(
                class_name=types[class_idx] if class_idx < len(types) else "",
                type_name=types[type_idx] if type_idx < len(types) else "",
                name=strings[name_idx] if name_idx < len(strings) else "",
            )
        )
    return out


def _parse_methods(
    data: bytes,
    off: int,
    count: int,
    strings: list[str],
    types: list[str],
    protos: list[str],
    dex: DexFile,
) -> list[MethodRef]:
    if count == 0 or off == 0:
        return []
    out: list[MethodRef] = []
    reader = Reader(data, off)
    for _ in range(count):
        try:
            class_idx = reader.u16()
            proto_idx = reader.u16()
            name_idx = reader.u32()
        except ParseError:
            dex.warnings.append("method_ids table truncated")
            break
        out.append(
            MethodRef(
                class_name=types[class_idx] if class_idx < len(types) else "",
                name=strings[name_idx] if name_idx < len(strings) else "",
                proto=protos[proto_idx] if proto_idx < len(protos) else "",
            )
        )
    return out


def _parse_class_defs(data: bytes, off: int, count: int, dex: DexFile) -> None:
    if count == 0 or off == 0:
        return
    types = dex.type_names
    strings = dex.strings
    reader = Reader(data, off)
    for _ in range(count):
        try:
            class_idx = reader.u32()
            access_flags = reader.u32()
            superclass_idx = reader.u32()
            interfaces_off = reader.u32()
            source_file_idx = reader.u32()
            reader.u32()  # annotations_off
            class_data_off = reader.u32()
            static_values_off = reader.u32()
        except ParseError:
            dex.warnings.append("class_defs table truncated")
            break

        descriptor = types[class_idx] if class_idx < len(types) else ""
        entry = DexClass(
            name=java_name(descriptor),
            descriptor=descriptor,
            superclass=(
                java_name(types[superclass_idx])
                if superclass_idx < len(types)
                else None
            ),
            source_file=(
                strings[source_file_idx] if source_file_idx < len(strings) else None
            ),
            access_flags=access_flags,
        )
        if interfaces_off:
            entry.interfaces = _parse_type_list(data, interfaces_off, types)
        dex.classes.append(entry)

        if class_data_off:
            try:
                _parse_class_data(data, class_data_off, entry, dex)
            except ParseError as exc:
                dex.warnings.append(f"class {entry.name}: {exc}")
        if static_values_off:
            try:
                _parse_static_values(data, static_values_off, entry, dex)
            except ParseError as exc:
                dex.warnings.append(f"class {entry.name} static values: {exc}")


def _parse_type_list(data: bytes, off: int, types: list[str]) -> list[str]:
    try:
        reader = Reader(data, off)
        size = reader.u32()
        if size > 65535:
            return []
        return [
            java_name(types[idx]) if idx < len(types) else ""
            for idx in (reader.u16() for _ in range(size))
        ]
    except ParseError:
        return []


def _parse_class_data(
    data: bytes, off: int, entry: DexClass, dex: DexFile
) -> None:
    reader = Reader(data, off)
    static_fields = reader.uleb128()
    instance_fields = reader.uleb128()
    direct_methods = reader.uleb128()
    virtual_methods = reader.uleb128()

    for total in (static_fields, instance_fields, direct_methods, virtual_methods):
        if total > 100_000:
            raise ParseError(f"class declares {total} members")

    # encoded_field: field_idx_diff, access_flags. Static field names are kept so
    # the encoded static-value array can be attributed to the right field.
    static_names: list[str] = []
    field_idx = 0
    for position in range(static_fields + instance_fields):
        if position == static_fields:
            field_idx = 0
        field_idx += reader.uleb128()
        reader.uleb128()
        if position < static_fields:
            ref = dex.field_refs[field_idx] if field_idx < len(dex.field_refs) else None
            static_names.append(ref.name if ref else f"field_{field_idx}")
    entry.static_field_names = static_names

    for count in (direct_methods, virtual_methods):
        method_idx = 0
        for _ in range(count):
            method_idx += reader.uleb128()
            access_flags = reader.uleb128()
            code_off = reader.uleb128()
            ref = (
                dex.method_refs[method_idx]
                if method_idx < len(dex.method_refs)
                else None
            )
            method = DexMethod(
                name=ref.name if ref else f"method_{method_idx}",
                class_name=entry.descriptor,
                proto=ref.proto if ref else "",
                access_flags=access_flags,
            )
            entry.methods.append(method)
            if code_off:
                site = CallSite(
                    class_name=entry.name,
                    method_name=method.name,
                    source_file=entry.source_file,
                )
                try:
                    _walk_code(data, code_off, site, dex, method)
                except ParseError:
                    # A single unreadable method body is not worth losing the class.
                    pass


def _parse_static_values(
    data: bytes, off: int, entry: DexClass, dex: DexFile
) -> None:
    """Read a class's `static_values` array and attribute string constants to fields.

    javac stores `static final String FOO = "..."` here rather than emitting a
    const-string, so this is where most hardcoded secrets actually live.
    """
    reader = Reader(data, off)
    size = reader.uleb128()
    if size > 100_000:
        raise ParseError(f"static value array declares {size} entries")
    for index in range(size):
        header = reader.u8()
        value_type = header & 0x1F
        value_arg = (header >> 5) & 0x07
        if value_type == VALUE_STRING:
            raw = reader.bytes(value_arg + 1)
            string_idx = int.from_bytes(raw, "little")
            field_name = (
                entry.static_field_names[index]
                if index < len(entry.static_field_names)
                else f"static_{index}"
            )
            _record(
                dex.string_sites,
                string_idx,
                CallSite(
                    class_name=entry.name,
                    method_name=field_name,
                    source_file=entry.source_file,
                    kind="field",
                ),
            )
        elif value_type in (VALUE_ARRAY, VALUE_ANNOTATION):
            # Nested structures need a full walk to skip correctly; stop here
            # rather than mis-parse the remainder of the array.
            return
        elif value_type in (VALUE_BOOLEAN, VALUE_NULL):
            continue  # payload is encoded in value_arg itself
        else:
            reader.bytes(value_arg + 1)


def _walk_code(
    data: bytes, off: int, site: CallSite, dex: DexFile, method: DexMethod | None = None
) -> None:
    """Decode one code_item, recording the refs it touches and what it does.

    A small register map is maintained while walking so that integer arguments to
    a call can be resolved. That is what turns "this app calls getSharedPreferences"
    into "this app calls getSharedPreferences(..., MODE_WORLD_READABLE)", and what
    lets `setJavaScriptEnabled(false)` be distinguished from `(true)`.
    """
    reader = Reader(data, off)
    reader.u16()  # registers_size
    reader.u16()  # ins_size
    reader.u16()  # outs_size
    tries_size = reader.u16()
    reader.u32()  # debug_info_off
    insns_size = reader.u32()

    if insns_size > _MAX_CODE_UNITS:
        raise ParseError(f"code item declares {insns_size} code units")
    insns_start = reader.pos
    insns_end = insns_start + insns_size * 2
    if insns_end > len(data):
        raise ParseError("code item overruns the buffer")
    _ = tries_size

    if method is not None:
        method.has_body = True
        method.insn_count = insns_size

    # register -> constant integer, valid only until the register is reassigned.
    registers: dict[int, int] = {}
    pos = insns_start
    while pos + 2 <= insns_end:
        unit = int.from_bytes(data[pos : pos + 2], "little")
        opcode = unit & 0xFF

        if opcode == 0x00 and unit != 0x0000:
            width = _payload_width(data, pos, unit, insns_end)
            if width <= 0:
                break
            pos += width * 2
            continue

        width = _WIDTHS[opcode]
        if pos + width * 2 > insns_end:
            break

        if opcode in _CONST_OPS:
            _track_const(data, pos, opcode, unit, registers)
        elif opcode in (0x1A, 0x1B):  # const-string / const-string/jumbo
            if opcode == 0x1A:
                string_idx = int.from_bytes(data[pos + 2 : pos + 4], "little")
            else:
                string_idx = int.from_bytes(data[pos + 2 : pos + 6], "little")
            registers.pop((unit >> 8) & 0xFF, None)
            _record(dex.string_sites, string_idx, site)
        elif opcode in _INVOKE_35C or opcode in _INVOKE_45CC:
            method_idx = int.from_bytes(data[pos + 2 : pos + 4], "little")
            _record(dex.call_sites, method_idx, site)
            args = _args_35c(data, pos, unit, registers)
            _record_invocation(dex, method_idx, site, args)
        elif opcode in _INVOKE_3RC:
            method_idx = int.from_bytes(data[pos + 2 : pos + 4], "little")
            _record(dex.call_sites, method_idx, site)
            args = _args_3rc(data, pos, unit, registers)
            _record_invocation(dex, method_idx, site, args)
        elif opcode in _FIELD_OPS:
            field_idx = int.from_bytes(data[pos + 2 : pos + 4], "little")
            _record(dex.field_sites, field_idx, site)
            # A read into a register invalidates any constant we were tracking.
            registers.pop((unit >> 8) & 0x0F, None)
        elif opcode in _MOVE_RESULT_OPS:
            registers.pop((unit >> 8) & 0xFF, None)

        pos += width * 2

    if method is not None:
        method.returns_const = _trivial_return(data, insns_start, insns_end)


def _track_const(
    data: bytes, pos: int, opcode: int, unit: int, registers: dict[int, int]
) -> None:
    """Record `const*` results so a later invoke can resolve its arguments."""
    try:
        if opcode == 0x12:  # const/4: 4-bit signed literal in the high nibble
            register = (unit >> 8) & 0x0F
            value = (unit >> 12) & 0x0F
            registers[register] = value - 16 if value > 7 else value
        elif opcode == 0x13:  # const/16
            register = (unit >> 8) & 0xFF
            raw = int.from_bytes(data[pos + 2 : pos + 4], "little")
            registers[register] = raw - 0x10000 if raw > 0x7FFF else raw
        elif opcode == 0x14:  # const
            register = (unit >> 8) & 0xFF
            registers[register] = int.from_bytes(data[pos + 2 : pos + 6], "little")
        elif opcode == 0x15:  # const/high16
            register = (unit >> 8) & 0xFF
            registers[register] = (
                int.from_bytes(data[pos + 2 : pos + 4], "little") << 16
            )
    except (IndexError, ValueError):
        pass


def _args_35c(
    data: bytes, pos: int, unit: int, registers: dict[int, int]
) -> tuple[int | None, ...]:
    """Resolve the argument registers of a format-35c invoke."""
    try:
        count = (unit >> 12) & 0x0F
        g = (unit >> 8) & 0x0F
        packed = int.from_bytes(data[pos + 4 : pos + 6], "little")
    except (IndexError, ValueError):
        return ()
    nibbles = [
        packed & 0x0F,
        (packed >> 4) & 0x0F,
        (packed >> 8) & 0x0F,
        (packed >> 12) & 0x0F,
        g,
    ]
    return tuple(registers.get(reg) for reg in nibbles[: min(count, 5)])


def _args_3rc(
    data: bytes, pos: int, unit: int, registers: dict[int, int]
) -> tuple[int | None, ...]:
    """Resolve the argument registers of a format-3rc (range) invoke."""
    try:
        count = (unit >> 8) & 0xFF
        first = int.from_bytes(data[pos + 4 : pos + 6], "little")
    except (IndexError, ValueError):
        return ()
    return tuple(registers.get(first + offset) for offset in range(min(count, 16)))


def _record_invocation(
    dex: DexFile, method_idx: int, site: CallSite, args: tuple[int | None, ...]
) -> None:
    records = dex.invocations.setdefault(method_idx, [])
    if len(records) < _MAX_CALL_SITES_PER_TARGET:
        records.append(Invocation(site=site, args=args))


def _trivial_return(data: bytes, start: int, end: int) -> int | None:
    """Classify a body that only returns, optionally returning a constant.

    `return-void` alone yields 0; `const/4 vX, N; return vX` yields N. Anything
    else yields None. This is how a do-nothing certificate check is recognised.
    """
    if start + 2 > end:
        return None
    first = int.from_bytes(data[start : start + 2], "little")
    opcode = first & 0xFF
    if opcode == 0x0E:  # return-void
        return 0
    if opcode == 0x12 and start + 4 <= end:  # const/4 then return
        second = int.from_bytes(data[start + 2 : start + 4], "little")
        if second & 0xFF in (0x0F, 0x11):  # return / return-object
            value = (first >> 12) & 0x0F
            return value - 16 if value > 7 else value
    return None


def _payload_width(data: bytes, pos: int, unit: int, end: int) -> int:
    """Code-unit width of a packed-switch / sparse-switch / fill-array-data payload."""
    try:
        if unit == 0x0100:  # packed-switch
            size = int.from_bytes(data[pos + 2 : pos + 4], "little")
            return size * 2 + 4
        if unit == 0x0200:  # sparse-switch
            size = int.from_bytes(data[pos + 2 : pos + 4], "little")
            return size * 4 + 2
        if unit == 0x0300:  # fill-array-data
            element_width = int.from_bytes(data[pos + 2 : pos + 4], "little")
            size = int.from_bytes(data[pos + 4 : pos + 8], "little")
            if element_width > 8 or size > _MAX_CODE_UNITS:
                return -1
            return (size * element_width + 1) // 2 + 4
    except (IndexError, ValueError):
        return -1
    return 1


def _record(index: dict[int, list[CallSite]], key: int, site: CallSite) -> None:
    sites = index.setdefault(key, [])
    if len(sites) < _MAX_CALL_SITES_PER_TARGET:
        # Avoid recording the same method twice when it calls a target in a loop.
        if not sites or sites[-1] != site:
            sites.append(site)
