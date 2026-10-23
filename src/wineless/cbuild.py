"""Runtime compilation of the C loader with a content-addressed cache."""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

LOADER_SRC = Path(__file__).resolve().parent.parent.parent / "c" / "wineless_loader.c"

_FALLBACK_CHAIN = ("cc", "gcc", "clang")


def find_compiler() -> str:
    for name in _FALLBACK_CHAIN:
        path = shutil.which(name)
        if path:
            return path
    raise RuntimeError(
        "no C compiler found (tried cc/gcc/clang). wineless compiles its "
        "loader at runtime — install gcc, e.g. `sudo apt install gcc`."
    )


def _source() -> str:
    if LOADER_SRC.exists():
        return LOADER_SRC.read_text(encoding="utf-8")
    # installed wheel without the C file? not supported loudly:
    raise FileNotFoundError(
        f"loader source not found at {LOADER_SRC}; run from a git checkout or "
        "install from source (pip install -e .)."
    )


def build_loader(force: bool = False) -> Path:
    """Compile ``c/wineless_loader.c`` and return the executable path.

    The binary is cached in ``$XDG_CACHE_HOME/wineless`` (or ``~/.cache``)
    keyed by the SHA-256 of the source, so repeated runs are instant.
    """
    src_text = _source()
    digest = hashlib.sha256(src_text.encode()).hexdigest()[:16]

    cache_dir = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "wineless"
    cache_dir.mkdir(parents=True, exist_ok=True)
    binary = cache_dir / f"wineless_loader_{digest}"

    if binary.exists() and not force:
        return binary

    cc = find_compiler()
    with tempfile.TemporaryDirectory() as td:
        src_file = Path(td) / "wineless_loader.c"
        src_file.write_text(src_text, encoding="utf-8")
        tmp_out = Path(td) / "loader"
        proc = subprocess.run(
            [cc, "-O2", "-rdynamic", "-no-pie", "-o", str(tmp_out), str(src_file), "-lm"],
            capture_output=True, text=True,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"C loader compilation failed:\n{proc.stderr}")
        shutil.copy2(tmp_out, binary)
    binary.chmod(0o755)
    return binary
