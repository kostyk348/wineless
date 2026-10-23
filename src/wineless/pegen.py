"""pegen — synthesize minimal Windows PE64 executables from pure Python.

Why? So that ``wineless`` can be tested *end to end* on any Linux box,
without MinGW, without Windows, without downloading anything.
The generated image is a real PE32+ binary: DOS header, COFF header,
PE32+ optional header, .text + .idata sections, a kernel32 import table
and honest x86-64 machine code that calls the imports through the IAT
(Microsoft x64 ABI, shadow space included).

It is also a neat educational artifact: the smallest possible "Hello, world"
PE you will ever meet (~1 KB).
"""

from __future__ import annotations

import struct

# --- layout constants -------------------------------------------------------
DOS_HEADER_SIZE = 0x80
FILE_ALIGN = 0x200
SECTION_ALIGN = 0x1000
TEXT_RVA = 0x1000
IDATA_RVA = 0x2000
DEFAULT_IMAGE_BASE = 0x400000

IMPORTS = ["GetStdHandle", "WriteFile", "ExitProcess"]


def _align(n: int, a: int) -> int:
    return (n + a - 1) // a * a


def _dos_header(e_lfanew: int) -> bytes:
    hdr = bytearray(DOS_HEADER_SIZE)
    hdr[0:2] = b"MZ"
    # classic DOS stub message for authenticity
    stub = b"This program cannot be run in DOS mode.\r\r\n$"
    hdr[0x4E:0x4E + len(stub)] = stub
    struct.pack_into("<I", hdr, 0x3C, e_lfanew)
    return bytes(hdr)


def _import_block() -> tuple[bytes, int, int, int]:
    """Build the .idata payload.

    Returns (blob, descriptors_off, descriptors_size, iat_off) where offsets are
    relative to the start of .idata (i.e. to IDATA_RVA).
    """
    dll_name = b"kernel32.dll\x00"
    # hint/name entries: 2-byte hint + name + NUL, each entry 2-byte aligned
    hn_blob = bytearray()
    hn_offsets = []
    for i, fn in enumerate(IMPORTS):
        hn_offsets.append(len(hn_blob))
        hn_blob += struct.pack("<H", i) + fn.encode() + b"\x00"
        if len(hn_blob) % 2:
            hn_blob += b"\x00"

    n = len(IMPORTS)
    assert n == 3, "pegen is tuned for exactly the GetStdHandle/WriteFile/ExitProcess trio"
    size_desc = 40  # 1 real descriptor + terminating null
    size_ilt = 8 * (n + 1)
    size_iat = size_ilt

    off_desc = 0
    off_ilt = _align(off_desc + size_desc, 8)
    off_iat = off_ilt + size_ilt
    off_dll = off_iat + size_iat
    off_hn = _align(off_dll + len(dll_name), 2)

    blob = bytearray(off_hn + len(hn_blob))

    # IMAGE_IMPORT_DESCRIPTOR: OFT, TimeDateStamp, ForwarderChain, Name, FirstThunk
    struct.pack_into("<IIIII", blob, off_desc,
                     IDATA_RVA + off_ilt, 0, 0,
                     IDATA_RVA + off_dll,
                     IDATA_RVA + off_iat)
    # terminating descriptor already zero

    # ILT entries -> RVA of hint/name
    for i, hoff in enumerate(hn_offsets):
        struct.pack_into("<Q", blob, off_ilt + i * 8, IDATA_RVA + off_hn + hoff)
        # IAT is resolved by the loader; keep same RVAs initially (loader overwrites)
        struct.pack_into("<Q", blob, off_iat + i * 8, IDATA_RVA + off_hn + hoff)

    blob[off_dll:off_dll + len(dll_name)] = dll_name
    blob[off_hn:off_hn + len(hn_blob)] = hn_blob

    return bytes(blob), off_desc, size_desc, off_iat


def build_pe(message: bytes = b"Hello from a synthetic PE64!\n",
             exit_code: int = 42,
             image_base: int = DEFAULT_IMAGE_BASE) -> bytes:
    """Return the bytes of a minimal, valid, runnable Windows PE64 executable.

    The entry point does exactly one thing:

        WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), message, len, &written, NULL)
        ExitProcess(exit_code)

    using the Microsoft x64 calling convention (shadow space allocated).
    """
    msg = message
    if not msg.endswith(b"\n"):
        msg += b"\n"

    # ---- machine code (two-pass for rip-relative displacements) ----------
    # Offsets inside .text:
    #   insns occupy the head, message payload is appended at the end.
    #
    #   0  : 48 83 EC 28           sub  rsp, 0x28            ; shadow space
    #   4  : B9 F5 FF FF FF        mov  ecx, -11             ; STD_OUTPUT_HANDLE
    #   9  : FF 15 d1              call [rip+d1]             ; GetStdHandle
    #   15 : 48 89 C1              mov  rcx, rax             ; handle
    #   18 : 48 8D 15 d2           lea  rdx, [rip+d2]        ; msg
    #   25 : 41 B8 LLLL            mov  r8d, len             ; msg length
    #   31 : 4C 8D 4C 24 20        lea  r9, [rsp+0x20]       ; &written
    #   36 : 48 C7 44 24 20 0...   mov  qword [rsp+0x20], 0
    #   45 : FF 15 d3              call [rip+d3]             ; WriteFile
    #   51 : B9 CCCCCCCC            mov  ecx, exit_code
    #   56 : FF 15 d4              call [rip+d4]             ; ExitProcess
    #   62 : <message bytes>

    off_call_getstd = 9
    off_after_getstd = off_call_getstd + 6
    off_lea_msg = 18
    off_after_lea = off_lea_msg + 7
    off_call_write = 45
    off_after_write = off_call_write + 6
    off_call_exit = 56
    off_after_exit = off_call_exit + 6
    off_msg = 62

    msg_len = len(msg)
    idata_blob, desc_off, desc_size, iat_off = _import_block()
    iat_rva = IDATA_RVA + iat_off

    def iat_slot(i: int) -> int:
        return iat_rva + i * 8

    text_rva = TEXT_RVA
    msg_rva = text_rva + off_msg

    d1 = iat_slot(0) - (text_rva + off_after_getstd)
    d2 = msg_rva - (text_rva + off_after_lea)
    d3 = iat_slot(1) - (text_rva + off_after_write)
    d4 = iat_slot(2) - (text_rva + off_after_exit)

    code = b"".join([
        b"\x48\x83\xEC\x28",                       # sub rsp, 0x28
        b"\xB9\xF5\xFF\xFF\xFF",                   # mov ecx, -11
        b"\xFF\x15", struct.pack("<i", d1),        # call GetStdHandle
        b"\x48\x89\xC1",                           # mov rcx, rax
        b"\x48\x8D\x15", struct.pack("<i", d2),    # lea rdx, [rip+msg]
        b"\x41\xB8", struct.pack("<I", msg_len),   # mov r8d, msg_len
        b"\x4C\x8D\x4C\x24\x20",                   # lea r9, [rsp+0x20]
        b"\x48\xC7\x44\x24\x20\x00\x00\x00\x00",   # mov qword [rsp+0x20], 0
        b"\xFF\x15", struct.pack("<i", d3),        # call WriteFile
        b"\xB9", struct.pack("<I", exit_code),     # mov ecx, exit_code
        b"\xFF\x15", struct.pack("<i", d4),        # call ExitProcess
        msg,
    ])
    assert len(code) == off_msg + msg_len, f"layout drift: {len(code)} != {off_msg + msg_len}"

    text_raw_size = _align(len(code), FILE_ALIGN)
    idata_raw_size = _align(len(idata_blob), FILE_ALIGN)

    headers_raw = DOS_HEADER_SIZE + 4 + 20 + 240 + 2 * 40  # = 0x1B8
    size_of_headers = _align(headers_raw, FILE_ALIGN)
    size_of_image = SECTION_ALIGN * 3  # headers + .text + .idata
    entry_rva = text_rva

    # ---- headers ---------------------------------------------------------
    out = bytearray()
    out += _dos_header(DOS_HEADER_SIZE)

    # PE signature
    out += b"PE\x00\x00"
    # COFF: machine, nsec, timestamp, symtab, nsyms, optsize, chars
    out += struct.pack("<HHIIIHH", 0x8664, 2, 0, 0, 0, 240, 0x0022)
    # Optional header PE32+
    opt = bytearray(240)
    struct.pack_into("<H", opt, 0, 0x20B)                 # magic PE32+
    opt[2] = 14                                           # linker major
    struct.pack_into("<I", opt, 4, text_raw_size)         # SizeOfCode
    struct.pack_into("<I", opt, 8, idata_raw_size)        # SizeOfInitializedData
    struct.pack_into("<I", opt, 16, entry_rva)            # AddressOfEntryPoint
    struct.pack_into("<I", opt, 20, text_rva)             # BaseOfCode
    struct.pack_into("<Q", opt, 24, image_base)           # ImageBase
    struct.pack_into("<I", opt, 32, SECTION_ALIGN)        # SectionAlignment
    struct.pack_into("<I", opt, 36, FILE_ALIGN)           # FileAlignment
    struct.pack_into("<H", opt, 40, 6)                    # OS major
    struct.pack_into("<H", opt, 48, 6)                    # Subsystem major
    struct.pack_into("<I", opt, 56, size_of_image)        # SizeOfImage
    struct.pack_into("<I", opt, 60, size_of_headers)      # SizeOfHeaders
    struct.pack_into("<H", opt, 68, 3)                    # Subsystem = WINDOWS_CUI
    struct.pack_into("<H", opt, 70, 0)                    # DllCharacteristics: no dynamic base
    struct.pack_into("<I", opt, 72, 0x100000)             # SizeOfStackReserve
    struct.pack_into("<I", opt, 76, 0x1000)               # SizeOfStackCommit
    struct.pack_into("<I", opt, 80, 0x100000)             # SizeOfHeapReserve
    struct.pack_into("<I", opt, 84, 0x1000)               # SizeOfHeapCommit
    struct.pack_into("<I", opt, 108, 16)                  # NumberOfRvaAndSizes
    # DataDirectory[1] = IMPORT
    struct.pack_into("<II", opt, 0x70 + 1 * 8, IDATA_RVA + desc_off, desc_size)
    out += bytes(opt)

    # Section headers
    def sec_hdr(name: bytes, vsize: int, va: int, rsize: int, rptr: int, chars: int) -> bytes:
        return struct.pack("<8sIIIIIIHHI", name, vsize, va, rsize, rptr,
                           0, 0, 0, 0, chars)

    out += sec_hdr(b".text", len(code), text_rva, text_raw_size, size_of_headers,
                   0x60000020)  # CODE | EXEC | READ
    out += sec_hdr(b".idata", len(idata_blob), IDATA_RVA, idata_raw_size,
                   size_of_headers + text_raw_size,
                   0xC0000040)  # INITIALIZED_DATA | READ | WRITE

    out += b"\x00" * (size_of_headers - len(out))

    # ---- section payloads -------------------------------------------------
    out += code + b"\xCC" * (text_raw_size - len(code))     # int3 padding
    out += idata_blob + b"\x00" * (idata_raw_size - len(idata_blob))

    return bytes(out)


if __name__ == "__main__":  # pragma: no cover
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "hello.exe"
    text = sys.argv[2].encode() if len(sys.argv) > 2 else b"Hello from a synthetic PE64!"
    with open(target, "wb") as fh:
        fh.write(build_pe(text))
    print(f"[+] wrote {target} ({len(build_pe(text))} bytes)")
