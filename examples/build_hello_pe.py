#!/usr/bin/env python3
"""Synthesize a minimal Windows PE64 and print its structure.

No Windows, no MinGW, no downloads — pure Python.
"""

from wineless.pe import parse_pe
from wineless.pegen import build_pe

blob = build_pe(b"Hello from a hand-crafted PE64!", exit_code=0)
with open("demo.exe", "wb") as fh:
    fh.write(blob)

pe = parse_pe("demo.exe")
print(pe.summary())
