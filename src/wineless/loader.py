"""High-level orchestration: parse, check, compile, execute."""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Sequence

from .cbuild import build_loader
from .pe import PEFormatError, parse_pe


@dataclass
class RunResult:
    exit_code: int
    stdout: str
    stderr: str

    def __str__(self) -> str:
        return f"exit_code={self.exit_code}\n--- stdout ---\n{self.stdout}--- stderr ---\n{self.stderr}"


class Runner:
    """Compile the loader once, reuse it for many PE files."""

    def __init__(self, force_build: bool = False, verbose: bool = True) -> None:
        self.loader_path = build_loader(force=force_build)
        self.verbose = verbose

    def run(self, exe: str | Path, args: Optional[Sequence[str]] = None,
            timeout: float = 30.0) -> RunResult:
        args = list(args or [])
        proc = subprocess.run(
            [str(self.loader_path), str(exe), *args],
            capture_output=True, text=True, timeout=timeout,
        )
        return RunResult(proc.returncode, proc.stdout, proc.stderr)

    def info(self, exe: str | Path) -> str:
        return parse_pe(str(exe)).summary()


def run(exe: str | Path, args: Optional[Sequence[str]] = None,
        verbose: bool = True) -> RunResult:
    """One-shot convenience wrapper."""
    return Runner(verbose=verbose).run(exe, args)


def check_platform() -> None:
    """Fail early with a human-readable message on unsupported platforms."""
    import platform
    if platform.system() != "Linux":
        raise RuntimeError(f"wineless targets Linux, got {platform.system()}")
    if platform.machine() not in ("x86_64", "AMD64"):
        raise RuntimeError(f"wineless targets x86_64, got {platform.machine()}")
    if not shutil.which("cc") and not shutil.which("gcc") and not shutil.which("clang"):
        raise RuntimeError("no C compiler found; install gcc first")


__all__ = ["Runner", "RunResult", "run", "check_platform", "PEFormatError"]
