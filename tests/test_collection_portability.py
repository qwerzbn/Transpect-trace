"""The portability check locates hooks from string anchors, read-only."""
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import check_collection_portability as port  # noqa: E402

TEXT_RVA, RDATA_RVA, PDATA_RVA = 0x1000, 0x2000, 0x3000


def _lea(rva: int, target: int, rex: int = 0x48, modrm: int = 0x05) -> bytes:
    return bytes((rex, 0x8D, modrm)) + struct.pack("<i", target - (rva + 7))


def test_hook_event_string_counts():
    data = b"PreToolUse\0PostToolUse\0PreToolUse\0UserPromptSubmit\0hooks.json"
    counts = port.string_counts(data)
    assert counts == {"UserPromptSubmit": 1, "PreToolUse": 2, "PostToolUse": 1,
                      "PreModelRequest": 0, "hooks.json": 1}
    assert port.classify_hook(True, counts) == "available"
    assert port.classify_hook(False, counts) == "unavailable(features.hooks=false)"
    assert port.classify_hook(True, {**counts, "PreToolUse": 0}).startswith(
        "unavailable(events missing: PreToolUse")


def test_rip_relative_lea_xref_to_anchor_on_synthetic_text():
    anchor = RDATA_RVA + 0x40
    text = bytearray(b"\x90" * 0x80)
    text[0x10:0x17] = _lea(TEXT_RVA + 0x10, anchor)                 # lea rax, [rip+anchor]
    text[0x20:0x27] = _lea(TEXT_RVA + 0x20, anchor - 8, rex=0x4C, modrm=0x0D)  # r9, literal tail
    text[0x30:0x37] = _lea(TEXT_RVA + 0x30, RDATA_RVA + 0x400)      # unrelated string
    text[0x40:0x47] = b"\x48\x8d\x44\x24\x10\x90\x90"               # lea rax, [rsp+10h]: not rip
    found = port.lea_xrefs(bytes(text), 0, len(text), TEXT_RVA, [(anchor - 32, anchor + 10)])
    assert found == {(anchor - 32, anchor + 10): [TEXT_RVA + 0x10, TEXT_RVA + 0x20]}


def test_pdata_function_lookup():
    raw = b"".join(struct.pack("<III", *entry) for entry in (
        (0x1100, 0x1180, 0), (0x1000, 0x1040, 0), (0, 0, 0), (0x1040, 0x1100, 0))) + b"\0" * 5
    starts, ends = port.parse_pdata(raw)
    assert list(starts) == [0x1000, 0x1040, 0x1100]
    assert port.function_containing(starts, ends, 0x1000) == (0x1000, 0x1040)
    assert port.function_containing(starts, ends, 0x1050) == (0x1040, 0x1100)
    assert port.function_containing(starts, ends, 0x1180) is None
    assert port.function_containing(starts, ends, 0x0FFF) is None


def _pe(path: Path, text: bytes, rdata: bytes, pdata: bytes) -> None:
    """Minimal PE32+ with .text/.rdata/.pdata, each 0x200 raw bytes."""
    header = bytearray(0x400)
    struct.pack_into("<I", header, 0x3C, 0x40)
    header[0x40:0x44] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", header, 0x44, 0x8664, 3, 0, 0, 0, 0xF0, 0x22)
    sections = ((b".text", TEXT_RVA, text), (b".rdata", RDATA_RVA, rdata),
                (b".pdata", PDATA_RVA, pdata))
    for index, (name, rva, data) in enumerate(sections):
        struct.pack_into("<8sIIII", header, 0x148 + index * 40, name, len(data), rva, 0x200,
                         0x400 + index * 0x200)
    path.write_bytes(bytes(header) + b"".join(data.ljust(0x200, b"\0") for _, _, data in sections))


def test_http_locator_on_synthetic_pe(tmp_path):
    anchor = RDATA_RVA + 0x20
    rdata = b"\0" * 0x20 + port.HTTP_ANCHOR.encode() + b"\0" + port.WSS_ANCHOR.encode()
    prefix = bytes.fromhex("5541574156415541")
    text = bytearray(b"\xcc" * 0x100)
    text[0x40:0x48] = prefix
    text[0x60:0x67] = _lea(TEXT_RVA + 0x60, anchor)
    pdata = struct.pack("<III", TEXT_RVA, TEXT_RVA + 0x40, 0) + struct.pack(
        "<III", TEXT_RVA + 0x40, TEXT_RVA + 0x100, 0)
    path = tmp_path / "codex.exe"
    _pe(path, bytes(text), rdata, pdata)
    with port.PEImage(path) as image:
        assert image.machine == 0x8664
        found = image.anchor_functions([port.HTTP_ANCHOR, port.WSS_ANCHOR])
        assert image.read(TEXT_RVA + 0x40, len(prefix)) == prefix
    assert found[port.HTTP_ANCHOR] == {"rdata_copies": 1, "functions": {
        (TEXT_RVA + 0x40, TEXT_RVA + 0x100): [TEXT_RVA + 0x60]}}
    assert found[port.WSS_ANCHOR] == {"rdata_copies": 1, "functions": {}}


def test_adapter_status_classification():
    validated = {"name": "a.json", "status": "validated"}
    candidate = {"name": "b.json", "status": "candidate_unvalidated"}
    ok, moved = {"http": True, "wss": True}, {"http": True, "wss": False}
    assert port.classify_native(validated, ok, True) == "validated"
    assert port.classify_native(candidate, ok, True) == "pinned_unvalidated"
    # Same code under another file hash (e.g. a VS Code copy): only the locator holds.
    assert port.classify_native(None, None, True) == "locator_only"
    assert port.classify_native(validated, moved, False) == "no_pin"
    assert port.classify_native(validated, ok, True, x64=False) == "no_pin"
    assert port.hooks_feature("apps  stable  true\nhooks                 stable  true\n") is True
    assert port.hooks_feature("hooks  stable  false") is False
    assert port.hooks_feature("error: unknown command") is None
