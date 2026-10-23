import pytest

from wineless.kernel import MetaKernel, demo, install_os_macros


def test_alloc_and_mutate():
    k = MetaKernel()
    rid = k.eval([":res/alloc", "stream", {"name": "a.bin"}])
    assert rid == "res_stream_1"
    assert k.eval([":res/mutate", rid, "payload", {"buffer": "x"}]) is True
    assert k.state[rid]["payload"] == {"buffer": "x"}


def test_mutate_unknown_resource_returns_false():
    k = MetaKernel()
    assert k.eval([":res/mutate", "res_ghost_99", "payload", 1]) is False


def test_signals_logged():
    k = MetaKernel()
    k.eval([":sig/emit", "res_x_1", "PING", 7])
    assert k.event_log == [("res_x_1", "PING", 7)]
    assert "PING" in k.eval([":sig/emit", "res_x_1", "PING", 7])


def test_seq_returns_last():
    k = MetaKernel()
    result = k.eval([":seq", [":res/alloc", "f", {}], [":res/alloc", "g", {}]])
    assert result == "res_g_2"


def test_unknown_primitive_raises():
    k = MetaKernel()
    with pytest.raises(ValueError):
        k.eval([":teleport", "nowhere"])


def test_os_macros_reduce_win32_and_posix():
    k = MetaKernel()
    install_os_macros(k)
    win = k.eval(["win32/CreateFileW", "data.bin", "GENERIC_WRITE", "FILE_SHARE_READ"])
    pos = k.eval(["posix/open", "/tmp/s", 0o666])
    assert win.startswith("res_stream_") and pos.startswith("res_stream_")
    # both write through the same universal macro
    k.eval(["os/write", win, "win payload"])
    k.eval(["os/write", pos, "posix payload"])
    assert k.state[win]["payload"] == {"buffer": "win payload"}
    assert any(ev[1] == "DATA_WRITTEN" for ev in k.event_log)


def test_demo_runs():
    text = demo()
    assert "Win32" in text and "POSIX" in text
