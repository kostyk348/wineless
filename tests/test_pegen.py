import pytest

from wineless.pegen import DOS_HEADER_SIZE, build_pe


def test_build_pe_size_and_alignment():
    blob = build_pe()
    # SizeOfHeaders (0x200) + .text (0x200) + .idata (0x200)
    assert len(blob) == 3 * 0x200
    assert len(blob) % 0x200 == 0


def test_build_pe_signatures():
    blob = build_pe()
    assert blob[:2] == b"MZ"
    e_lfanew = int.from_bytes(blob[0x3C:0x40], "little")
    assert blob[e_lfanew:e_lfanew + 4] == b"PE\x00\x00"


def test_message_is_embedded():
    msg = b"The cake is a lie"
    blob = build_pe(msg)
    assert msg in blob


def test_deterministic_output():
    assert build_pe(b"same") == build_pe(b"same")


@pytest.mark.parametrize("exit_code", [0, 1, 42, 255])
def test_exit_code_laid_out(exit_code):
    blob = build_pe(exit_code=exit_code)
    # the `mov ecx, imm32` at .text offset 51..56 encodes the exit code little-endian
    stored = int.from_bytes(blob[0x200 + 52:0x200 + 56], "little")
    assert stored == exit_code
