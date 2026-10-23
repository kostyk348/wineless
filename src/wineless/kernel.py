"""The Lisp meta-kernel: a tiny evaluator with three primitives.

The philosophical core of ``wineless``: any OS syscall — Win32 ``CreateFileW``
or POSIX ``open()`` — is just sugar over three universal operations:

    :res/alloc   — allocate a resource (file, stream, memory, socket...)
    :res/mutate  — mutate the state of a resource
    :sig/emit    — emit an event/signal to another resource

Everything else (files, sockets, IPC) can be expressed as macros that expand
into compositions of these primitives. Win32 and POSIX stop being different
worlds and become two macro packages over one kernel.
"""

from __future__ import annotations

import pprint
from typing import Any, Callable, Dict, List, Union

Expr = Union[list, tuple, str, int, float, bool, None]


class MetaKernel:
    """An evaluator over three primitives plus meta-combinators."""

    def __init__(self) -> None:
        self.state: Dict[str, Dict[str, Any]] = {}
        self.counter = 0
        self.event_log: List[tuple] = []
        self.macros: Dict[str, Callable[..., Expr]] = {}
        self._vars: Dict[str, Any] = {}

    # ------------------------------------------------------------------
    # primitives
    # ------------------------------------------------------------------
    def _resolve(self, expr: Expr) -> Any:
        """Strings of the form ':name' refer to :let-bound variables."""
        if isinstance(expr, str) and expr.startswith(":") and expr[1:] in self._vars:
            return self._vars[expr[1:]]
        return expr

    def eval(self, expr: Expr) -> Any:
        if not isinstance(expr, (list, tuple)):
            return self._resolve(expr)

        op, args = expr[0], expr[1:]

        if op == ":res/alloc":
            type_tag, init_val = args
            self.counter += 1
            res_id = f"res_{type_tag}_{self.counter}"
            self.state[res_id] = {"type": type_tag, "payload": self.eval(init_val)}
            return res_id

        if op == ":res/mutate":
            res_id, key, val = self.eval(args[0]), args[1], self.eval(args[2])
            if res_id in self.state:
                self.state[res_id][key] = val
                return True
            return False

        if op == ":sig/emit":
            target, event, payload = self.eval(args[0]), args[1], self.eval(args[2])
            self.event_log.append((target, event, payload))
            return f"[SIGNAL] -> {target} :: event '{event}' with data: {payload}"

        if op == ":let":
            name, value_expr, *body = args
            self._vars[name] = self.eval(value_expr)
            try:
                result = None
                for step in body:
                    result = self.eval(step)
                return self._vars[name] if not body else result
            finally:
                self._vars.pop(name, None)

        if op == ":seq":
            result = None
            for step in args:
                result = self.eval(step)
            return result

        if op == ":macro/expand":
            macro_fn, call_args = args
            return self.eval(macro_fn(*call_args))

        if isinstance(op, str) and op in self.macros:
            return self.eval(self.macros[op](*args))

        raise ValueError(f"unknown kernel primitive: {op!r}")

    # ------------------------------------------------------------------
    # macro registration
    # ------------------------------------------------------------------
    def register_macro(self, name: str, fn: Callable[..., Expr]) -> None:
        self.macros[name] = fn

    # ------------------------------------------------------------------
    # introspection helpers (nice for demos and tests)
    # ------------------------------------------------------------------
    def resources(self) -> List[str]:
        return list(self.state)

    def dump_state(self) -> str:
        return pprint.pformat(self.state)


# ----------------------------------------------------------------------
# Built-in macro pack: Win32 and POSIX as sugar over the kernel
# ----------------------------------------------------------------------
def install_os_macros(k: MetaKernel) -> None:
    """Register Win32/POSIX macros that expand into kernel primitives."""

    def win32_CreateFileW(filename: str, access: str, share_mode: str) -> Expr:
        # CreateFileW returns a HANDLE: bind the allocation, emit the event,
        # return the handle (so the caller can WriteFile into it).
        return [
            ":let", "h",
            [":res/alloc", "stream", {"name": filename, "buffer": "", "lock": share_mode}],
            [":sig/emit", ":h", "FILE_OPENED", {"access": access}],
            ":h",
        ]

    def posix_open(path: str, flags: int) -> Expr:
        return [":res/alloc", "stream", {"name": path, "buffer": "", "flags": flags}]

    def universal_write(handle: str, data: str) -> Expr:
        return [
            ":let", "h", handle,
            [":res/mutate", ":h", "payload", {"buffer": data}],
            [":sig/emit", ":h", "DATA_WRITTEN", len(data)],
            ":h",
        ]

    k.register_macro("win32/CreateFileW", win32_CreateFileW)
    k.register_macro("posix/open", posix_open)
    k.register_macro("os/write", universal_write)


def demo() -> str:
    """Run the classic demo: Win32 and POSIX calls reduce to one basis."""
    k = MetaKernel()
    install_os_macros(k)

    out: List[str] = []

    win_handle = k.eval(["win32/CreateFileW", "data.bin", "GENERIC_WRITE", "FILE_SHARE_READ"])
    out.append(f"Win32 CreateFileW('data.bin')  -> {win_handle}")

    posix_fd = k.eval(["posix/open", "/tmp/socket", 0o666])
    out.append(f"POSIX open('/tmp/socket')      -> {posix_fd}")

    r1 = k.eval(["os/write", win_handle, "Windows-originated payload"])
    r2 = k.eval(["os/write", posix_fd, "POSIX-originated payload"])
    out.append(f"os/write #1 -> {r1}")
    out.append(f"os/write #2 -> {r2}")
    out.append("--- kernel state ---")
    out.append(k.dump_state())
    return "\n".join(out)
