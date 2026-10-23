<div align="center">

```
 ██╗    ██╗██╗███╗   ██╗███████╗██╗     ███████╗███████╗
 ██║    ██║██║████╗  ██║██╔════╝██║     ██╔════╝██╔════╝
 ██║ █╗ ██║██║██╔██╗ ██║█████╗  ██║     █████╗  ███████╗
 ██║███╗██║██║██║╚██╗██║██╔══╝  ██║     ██╔══╝  ╚════██║
 ╚███╔███╔╝██║██║ ╚████║███████╗███████╗███████╗███████║
  ╚══╝╚══╝ ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝╚══════╝╚══════╝
```

# wineless

**Run Windows x64 PE binaries on Linux. No Wine. No VM. One C file.**

[![CI](https://github.com/example/wineless/actions/workflows/ci.yml/badge.svg)](https://github.com/example/wineless/actions)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-linux%20x86__64-black)]()
[![Python](https://img.shields.io/badge/python-3.9%2B-green)]()

*README на русском: [README.ru.md](README.ru.md)*

</div>

---

## TL;DR

```console
$ ./examples/run_jq.sh
[wineless] base=0x140000000 entry_rva=0x13f0 cmdline='"jq.exe" --version'
[wineless] executing PE entry point...
jq-1.7.1
[wineless] ExitProcess(0) captured

$ echo $?
0
```

That is the **official Microsoft-compiled `jq.exe`** (985 KB, MSVC, full CRT)
running natively on Linux. Wine is not involved — there is no Wine process,
no container, no emulation layer. Just a ~800-line C loader that:

1. parses the PE64 headers itself,
2. maps sections into anonymous memory,
3. applies `DIR64` base relocations,
4. resolves imports against a hand-written `ms_abi` hook table,
5. installs a fake **TEB/PEB** (with a working TLS array!) via `arch_prctl`,
6. jumps to the entry point and captures `ExitProcess()` with `setjmp/longjmp`.

And since we refuse to require Windows *or* MinGW, wineless ships with
**`pegen`** — a pure-Python generator of minimal PE64 binaries — so the
entire pipeline is testable on any Linux box, end to end, offline.

```console
$ wineless synth demo.exe "hello from a hand-crafted PE"
[+] synthesized demo.exe (1536 bytes)
$ wineless run demo.exe
hello from a hand-crafted PE
$ echo $?
42
```

## Why

Wine is a 30-year-old, 4-million-line behemoth. Sometimes you want the
*opposite*: the smallest possible bridge between a Windows binary and the
Linux kernel, small enough to read in one sitting. wineless is that bridge,
built as a research artifact:

- **Understand the PE format** by loading one manually — headers, sections,
  relocations, IAT, TLS.
- **Understand the ABI boundary**: every hook is declared `ms_abi`, so the
  same C file serves a Microsoft-calling-convention guest on a
  System-V host. The CRT bridge (memcpy, qsort, printf) is the hard part —
  see [How it works](#how-it-works).
- **Understand what an OS really is**: the notebook that started this
  project (`notebooks/01_meta_kernel_pe_loader.ipynb`) derives file/stream
  APIs down to three Lisp primitives — `:res/alloc`, `:res/mutate`,
  `:sig/emit` — and shows Win32 and POSIX as two macro packages over the
  same kernel.

## Architecture

```
                    wineless run jq.exe --version
                              │
                              ▼
  ┌──────────────────────────── Python orchestration ─────────────────────┐
  │  cli.py ─► loader.py ─► cbuild.py (cc -O2, cached by source hash)     │
  │     │            │                                                    │
  │     │            └──► pe.py     pure-Python PE32+ parser            │
  │     └──► kernel.py  Lisp meta-kernel (:res/alloc/:res/mutate/:sig/emit)│
  │              └──► pegen.py  minimal PE64 synthesizer (tests & demos)  │
  └───────────────────────────────┬───────────────────────────────────────┘
                                  │ subprocess
                                  ▼
  ┌────────────────────────── wineless_loader.c ──────────────────────────┐
  │  1. read PE      MZ → PE\0\0 → COFF → Optional(PE32+) → sections      │
  │  2. mmap image   preferred ImageBase, fallback anywhere               │
  │  3. copy + reloc headers, sections, DIR64 base relocations            │
  │  4. resolve IAT  250+ ms_abi hooks: kernel32 + ucrtbase + libm        │
  │  5. fake TEB/PEB arch_prctl(ARCH_SET_GS) + ThreadLocalStoragePointer  │
  │  6. entry()      setjmp/longjmp trap for ExitProcess()                │
  └───────────────────────────────────────────────────────────────────────┘
```

## How it works

**The ABI boundary.** A Windows binary expects Microsoft x64 convention:
integer args in `rcx, rdx, r8, r9`, floats in `xmm0..3`, 32-byte shadow
space. Our hooks are compiled with GCC's `__attribute__((ms_abi))`, which
handles the translation. But there are traps everywhere:

- **`wchar_t` is 2 bytes on Windows, 4 on Linux.** Every wide-string hook
  (`GetCommandLineW`, `MultiByteToWideChar`, `wcslen`...) speaks UTF-16
  explicitly through a `uint16_t` type — the naive `wchar_t*` version
  crashes spectacularly.
- **`__p___argv` returns `char***`**, not `char**` — UCRT returns the
  *address of the variable*, and MSVC startup code dereferences it twice.
- **`qsort` takes a comparator pointer** that will be *called back* — libc
  `qsort` would invoke a Microsoft-convention comparator with System-V
  arguments. wineless ships its own insertion sort that calls the
  comparator through an `ms_abi` function pointer.
- **MSVC forwards `printf` through `__stdio_common_vfprintf`** with an
  MS-ABI `va_list`. GCC has no `ms_vsnprintf`, so wineless re-declares the
  hook as an ms-variadic function and walks the format string itself,
  extracting arguments with `__builtin_va_arg`.

**The meta-kernel.** `wineless kernel` runs the philosophical demo: Win32
`CreateFileW` and POSIX `open()` expand into the same three primitives:

```lisp
(:let h
  (:res/alloc "stream" {:name "data.bin" :lock "FILE_SHARE_READ"})
  (:sig/emit :h "FILE_OPENED" {:access "GENERIC_WRITE"})
  :h)
```

An OS call is a resource allocation plus a signal. Everything else is
macros.

## Benchmarks

| workload                                   | time          | notes                            |
|--------------------------------------------|---------------|----------------------------------|
| `wineless run demo.exe` (synthetic PE)     | ~1 ms         | includes loader startup          |
| `wineless run jq.exe --version` (official) | ~10 ms        | 210 imports resolved, exit 0     |
| loader compile (cached)                    | ~0.4 s once   | re-hashed on every source change |

Hardware-dependent, of course — this is an emulator, not a race.

## Install

```bash
git clone https://github.com/example/wineless
cd wineless
pip install -e .
wineless --help
```

Requirements: Linux x86_64, any C compiler (`cc`/`gcc`/`clang`), Python 3.9+.
No other dependencies.

## CLI reference

```
wineless info   <file.exe>            dump PE headers, sections, imports
wineless run    <file.exe> [args...]  execute a Windows PE64 binary
wineless synth  <out.exe> [message]   synthesize a minimal demo PE (pure Python)
wineless kernel                       run the Lisp meta-kernel demo
```

Environment: `WINELESS_TRACE=1` enables call tracing (`wcslen` probes,
`GetProcAddress` misses) — invaluable when porting a new binary.

## What works / what doesn't

| ✅ works                                                | ❌ not yet                              |
|---------------------------------------------------------|------------------------------------------|
| synthetic PE64 generated by `pegen` (any Linux box)     | PE32 (32-bit) images                     |
| MSVC-built console binaries: `jq.exe --version`         | full ucrtbase locale/stdio semantics     |
| CRT bridge: memory, strings, `printf`, `qsort`, libm    | exceptions / SEH (swallowed)             |
| base relocations, static TLS array, console handles     | threads (`_beginthreadex` is a no-op)    |
| TEB/PEB layout with correct x64 offsets                 | GUI subsystem, GDI                       |

Roadmap ideas: read `argv` from the real OS environment for `main()`,
PE32 support, a syscall-trace mode, module loading of real DLLs.

## Repository layout

```
wineless/
├── c/wineless_loader.c        the loader (one file, ~900 lines)
├── src/wineless/              Python package
│   ├── pe.py                  PE32+ parser
│   ├── pegen.py               minimal PE64 generator
│   ├── kernel.py              Lisp meta-kernel
│   ├── cbuild.py              runtime compile + cache
│   ├── loader.py              orchestration
│   └── cli.py                 argparse CLI
├── tests/                     23 pytest cases incl. end-to-end PE execution
├── examples/                  build_hello_pe.py, run_jq.sh
├── notebooks/                 the original research notebook (Colab)
└── .github/workflows/ci.yml   unit + jq.exe integration on ubuntu-latest
```

## Related work

- [Wine](https://www.winehq.org) — the complete implementation; wineless is
  the anti-Wine: minimum viable emulation for research, not compatibility.
- [Fex-Emu](https://fex-emu.com), [Box64](https://github.com/ptitSeb/box64) —
  instruction-level emulators; wineless never emulates instructions (x64
  runs natively), it only supplies the *environment*.
- *Practical Binary Analysis* (Dennis Yurichev) — the PE homework this
  project accidentally turned into.

## License

Apache-2.0 — see [LICENSE](LICENSE).
Research artifact: expect rough edges, read the source, break things.
