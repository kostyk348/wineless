"""End-to-end: synthesize a PE64 with pure Python, execute it on Linux
through the wineless C loader. No Windows. No Wine. No MinGW."""

import subprocess

import pytest

from wineless.loader import Runner, check_platform
from wineless.pegen import build_pe

pytestmark = pytest.mark.skipif(
    subprocess.run(["which", "cc"], capture_output=True).returncode != 0
    and subprocess.run(["which", "gcc"], capture_output=True).returncode != 0,
    reason="no C compiler available",
)


@pytest.fixture(scope="module")
def runner():
    check_platform()
    return Runner()


@pytest.fixture(scope="module")
def hello_exe(tmp_path_factory):
    p = tmp_path_factory.mktemp("e2e") / "hello.exe"
    p.write_bytes(build_pe(b"[PE] hello from ring 3"))
    return str(p)


def test_synthetic_pe_runs_and_writes(runner, hello_exe):
    res = runner.run(hello_exe)
    assert "[PE] hello from ring 3" in res.stdout
    assert res.exit_code == 42
    assert "ExitProcess(42) captured" in res.stderr


def test_exit_code_propagates(runner, tmp_path):
    exe = tmp_path / "code7.exe"
    exe.write_bytes(build_pe(b"bye", exit_code=7))
    assert runner.run(str(exe)).exit_code == 7


def test_info_reports_imports(runner, hello_exe):
    text = runner.info(hello_exe)
    assert "kernel32.dll" in text
    assert "GetStdHandle" in text
