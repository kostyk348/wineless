import pytest

from wineless.pe import PEFormatError, parse_pe
from wineless.pegen import build_pe


@pytest.fixture(scope="module")
def pe_file(tmp_path_factory):
    path = tmp_path_factory.mktemp("pe") / "hello.exe"
    path.write_bytes(build_pe(b"parse me"))
    return str(path)


def test_parses_synthetic_pe(pe_file):
    pe = parse_pe(pe_file)
    assert pe.is_x64
    assert pe.entry_rva == 0x1000
    assert pe.image_base == 0x400000
    assert pe.size_of_image == 0x3000
    assert [s.name for s in pe.sections] == [".text", ".idata"]
    assert pe.sections[0].executable and not pe.sections[0].writable
    assert pe.sections[1].writable


def test_imports_resolved(pe_file):
    pe = parse_pe(pe_file)
    assert len(pe.imports) == 1
    imp = pe.imports[0]
    assert imp.dll == "kernel32.dll"
    assert imp.functions == ["GetStdHandle", "WriteFile", "ExitProcess"]


def test_summary_contains_key_fields(pe_file):
    text = parse_pe(pe_file).summary()
    assert "x64 (AMD64)" in text
    assert "WINDOWS_CUI" in text
    assert "kernel32.dll" in text


def test_rejects_garbage(tmp_path):
    bad = tmp_path / "bad.exe"
    bad.write_bytes(b"ELF garbage here" * 10)
    with pytest.raises(PEFormatError):
        parse_pe(str(bad))


def test_rejects_truncated_mz(tmp_path):
    bad = tmp_path / "mz.exe"
    bad.write_bytes(b"MZ" + b"\x00" * 10)
    with pytest.raises(PEFormatError):
        parse_pe(str(bad))
