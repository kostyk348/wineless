"""Pure-Python PE32+ (x64) header parser.

Enough of the PE format to understand what a loader must do before touching
machine code: DOS header, COFF header, Optional header (PE32+), section table,
data directories and the import table (DLL + function names).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import List, Tuple

MACHINE_NAMES = {
    0x8664: "x64 (AMD64)",
    0x014C: "x86 (i386)",
    0xAA64: "ARM64",
}

SUBSYSTEM_NAMES = {
    1: "NATIVE",
    2: "WINDOWS_GUI",
    3: "WINDOWS_CUI",
    7: "POSIX_CUI",
    16: "WINDOWS_BOOT_APPLICATION",
}

DIRECTORY_NAMES = [
    "EXPORT", "IMPORT", "RESOURCE", "EXCEPTION", "SECURITY", "BASERELOC",
    "DEBUG", "ARCHITECTURE", "GLOBALPTR", "TLS", "LOAD_CONFIG", "BOUND_IMPORT",
    "IAT", "DELAY_IMPORT", "COM_DESCRIPTOR", "RESERVED",
]


class PEFormatError(ValueError):
    """Raised when the file is not a valid PE32+ binary."""


@dataclass
class Section:
    name: str
    virtual_size: int
    virtual_address: int
    raw_size: int
    raw_ptr: int
    characteristics: int

    @property
    def writable(self) -> bool:
        return bool(self.characteristics & 0x80000000)

    @property
    def executable(self) -> bool:
        return bool(self.characteristics & 0x20000000)

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        flags = "".join(["x" if self.executable else "-", "w" if self.writable else "-"])
        return f"{self.name:<8} va=0x{self.virtual_address:06X} raw=0x{self.raw_size:06X} [{flags}]"


@dataclass
class Import:
    dll: str
    functions: List[str] = field(default_factory=list)


@dataclass
class PEBinary:
    """Parsed PE32+ image."""

    path: str
    machine: int
    num_sections: int
    entry_rva: int
    image_base: int
    size_of_image: int
    size_of_headers: int
    subsystem: int
    dll_characteristics: int
    sections: List[Section]
    directories: List[Tuple[int, int]]  # (rva, size), 16 entries
    imports: List[Import]
    has_relocations: bool

    @property
    def machine_name(self) -> str:
        return MACHINE_NAMES.get(self.machine, f"0x{self.machine:04X}")

    @property
    def subsystem_name(self) -> str:
        return SUBSYSTEM_NAMES.get(self.subsystem, f"0x{self.subsystem:X}")

    @property
    def is_x64(self) -> bool:
        return self.machine == 0x8664

    def summary(self) -> str:
        lines = [
            f"PE file        : {self.path}",
            f"Machine        : {self.machine_name}",
            f"Entry point    : RVA 0x{self.entry_rva:X}",
            f"ImageBase      : 0x{self.image_base:X}",
            f"SizeOfImage    : 0x{self.size_of_image:X}",
            f"Subsystem      : {self.subsystem_name}",
            f"Relocations    : {'yes' if self.has_relocations else 'no'}",
            f"Sections       : {self.num_sections}",
        ]
        for s in self.sections:
            lines.append(f"  {s}")
        imp = self.imports
        if imp:
            lines.append(f"Imports        : {sum(len(i.functions) for i in imp)} functions "
                         f"from {len(imp)} DLLs")
            for i in imp:
                lines.append(f"  {i.dll}: {', '.join(i.functions)}")
        return "\n".join(lines)


def parse_pe(path: str) -> PEBinary:
    """Parse a PE32+ file. Raises :class:`PEFormatError` on anything else."""
    with open(path, "rb") as fh:
        data = fh.read()

    if len(data) < 0x40 or data[:2] != b"MZ":
        raise PEFormatError("missing MZ signature (not a DOS/PE file)")

    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 24 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        raise PEFormatError("missing PE signature")

    coff = e_lfanew + 4
    machine, num_sections, _ts, _sym, _nsym, opt_size, _chars = struct.unpack_from(
        "<HHIIIHH", data, coff)

    opt = coff + 20
    if opt_size < 112 or len(data) < opt + opt_size:
        raise PEFormatError("optional header truncated")
    magic = struct.unpack_from("<H", data, opt)[0]
    if magic != 0x20B:
        raise PEFormatError(f"only PE32+ (magic 0x20B) is supported, got 0x{magic:X}")

    (entry_rva,) = struct.unpack_from("<I", data, opt + 0x10)
    (image_base,) = struct.unpack_from("<Q", data, opt + 0x18)
    (size_of_image,) = struct.unpack_from("<I", data, opt + 0x38)
    (size_of_headers,) = struct.unpack_from("<I", data, opt + 0x3C)
    (subsystem, dll_characteristics) = struct.unpack_from("<HH", data, opt + 0x44)

    directories: List[Tuple[int, int]] = []
    for i in range(16):
        rva, size = struct.unpack_from("<II", data, opt + 0x70 + i * 8)
        directories.append((rva, size))

    sections: List[Section] = []
    sec_tbl = opt + opt_size
    for i in range(num_sections):
        off = sec_tbl + i * 40
        if off + 40 > len(data):
            raise PEFormatError("section table truncated")
        name_raw = data[off:off + 8].rstrip(b"\x00")
        name = name_raw.decode("latin-1")
        vsize, va, rsize, rptr = struct.unpack_from("<IIII", data, off + 8)
        (chars,) = struct.unpack_from("<I", data, off + 36)
        sections.append(Section(name, vsize, va, rsize, rptr, chars))

    # --- imports -------------------------------------------------------
    imports: List[Import] = []
    imp_rva = directories[1][0]
    if imp_rva:

        def _rva2off(rva: int) -> int:
            for s in sections:
                if s.virtual_address <= rva < s.virtual_address + max(s.virtual_size, s.raw_size):
                    return s.raw_ptr + (rva - s.virtual_address)
            raise PEFormatError(f"RVA 0x{rva:X} not mapped by any section")

        desc_off = _rva2off(imp_rva)
        while desc_off + 20 <= len(data):
            oft, _ts, _fc, name_rva, ft = struct.unpack_from("<IIIII", data, desc_off)
            if not oft and not ft and not name_rva:
                break
            dll = data[_rva2off(name_rva):].split(b"\x00", 1)[0].decode("latin-1")
            thunk_rva = oft or ft
            t_off = _rva2off(thunk_rva)
            funcs: List[str] = []
            while t_off + 8 <= len(data):
                (thunk,) = struct.unpack_from("<Q", data, t_off)
                if thunk == 0:
                    break
                if not (thunk >> 63):  # import by name
                    nm = data[_rva2off(thunk & 0x7FFFFFFF) + 2:]
                    funcs.append(nm.split(b"\x00", 1)[0].decode("latin-1"))
                else:
                    funcs.append(f"ordinal#{thunk & 0xFFFF}")
                t_off += 8
            imports.append(Import(dll, funcs))
            desc_off += 20

    has_relocs = directories[5][0] != 0

    return PEBinary(
        path=path,
        machine=machine,
        num_sections=num_sections,
        entry_rva=entry_rva,
        image_base=image_base,
        size_of_image=size_of_image,
        size_of_headers=size_of_headers,
        subsystem=subsystem,
        dll_characteristics=dll_characteristics,
        sections=sections,
        directories=directories,
        imports=imports,
        has_relocations=has_relocs,
    )
