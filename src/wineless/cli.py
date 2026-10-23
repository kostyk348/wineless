"""wineless CLI.

    wineless info   <file.exe>            — dump PE headers / sections / imports
    wineless run    <file.exe> [args...]  — execute a Windows PE64 on Linux
    wineless synth  <out.exe> [message]   — synthesize a minimal demo PE (no Windows needed)
    wineless kernel                       — run the Lisp meta-kernel demo
"""

from __future__ import annotations

import argparse
import sys

from .kernel import demo as kernel_demo
from .loader import Runner, check_platform
from .pe import PEFormatError, parse_pe
from .pegen import build_pe


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="wineless",
        description="Run Windows x64 PE binaries on Linux — no Wine, no VM.",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_info = sub.add_parser("info", help="dump PE headers/sections/imports")
    p_info.add_argument("exe")

    p_run = sub.add_parser("run", help="execute a Windows PE64 binary")
    p_run.add_argument("exe")
    p_run.add_argument("args", nargs="*", help="arguments passed to GetCommandLineA")

    p_synth = sub.add_parser("synth", help="build a minimal demo PE64 with pure Python")
    p_synth.add_argument("out")
    p_synth.add_argument("message", nargs="?", default="Hello from a synthetic PE64!")

    sub.add_parser("kernel", help="run the Lisp meta-kernel demo")

    ns = parser.parse_args(argv)

    if ns.cmd == "kernel":
        print(kernel_demo())
        return 0

    if ns.cmd == "synth":
        blob = build_pe(ns.message.encode())
        with open(ns.out, "wb") as fh:
            fh.write(blob)
        print(f"[+] synthesized {ns.out} ({len(blob)} bytes)")
        return 0

    check_platform()

    if ns.cmd == "info":
        try:
            print(parse_pe(ns.exe).summary())
        except (PEFormatError, OSError) as exc:
            print(f"[-] {exc}", file=sys.stderr)
            return 1
        return 0

    # run
    try:
        runner = Runner()
    except (RuntimeError, FileNotFoundError) as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return 1
    result = runner.run(ns.exe, ns.args)
    sys.stdout.write(result.stdout)
    sys.stdout.flush()
    return result.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
