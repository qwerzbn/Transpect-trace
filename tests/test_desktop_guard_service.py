"""Production desktop guard: pins, local build, discovery helpers, decision log."""
from __future__ import annotations

import json
from pathlib import Path
import struct
from types import SimpleNamespace

import pytest

from transpect_trace.guard import desktop_service as svc

ROOT = Path(__file__).resolve().parents[1]


def _pin(directory: Path, **changes) -> Path:
    value = json.loads((ROOT / "deploy/desktop-guard/26.1103.3517.0.json").read_text("utf-8"))
    value.update(changes)
    path = directory / "pin.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def _pe(path: Path, rva: int, payload: bytes) -> Path:
    """Minimal PE32+ with one section mapping `rva` to file offset 0x400."""
    data = bytearray(0x400 + 0x1000)
    pe = 0x80
    data[0x3C:0x40] = struct.pack("<I", pe)
    data[pe:pe + 4] = b"PE\0\0"
    struct.pack_into("<HH", data, pe + 4, 0x8664, 1)
    struct.pack_into("<H", data, pe + 20, 0xF0)
    section = pe + 24 + 0xF0
    data[section:section + 8] = b".text\0\0\0"
    base = rva & ~0xFFF
    struct.pack_into("<IIII", data, section + 8, 0x1000, base, 0x1000, 0x400)
    offset = 0x400 + rva - base
    data[offset:offset + len(payload)] = payload
    path.write_bytes(bytes(data))
    return path


def test_repository_pin_is_valid_and_keyed_by_backend_hash():
    pins = svc.load_pins()
    pin = pins["40ecc3d8b6899afd8f935a8cccb7d53ba41ffd7c199f679e186d30ddd0d0bf39"]
    assert pin["codex_desktop_version"] == "26.1103.3517.0"
    assert set(pin["hooks"]) == set(svc.HOOK_NAMES)


@pytest.mark.parametrize("changes", [
    {"schema": "other"},
    {"hooks": {"http": {"rva": "0x10", "prefix_hex": "5541"}}},
    {"abi": {"http_denied_tag": "3", "wss_success_tag": 32, "wss_denied_tag": 25}},
])
def test_malformed_pins_are_rejected(tmp_path, changes):
    _pin(tmp_path, **changes)
    with pytest.raises(ValueError, match="invalid desktop guard pin"):
        svc.load_pins(tmp_path)


def test_empty_pin_directory_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="no desktop guard pins"):
        svc.load_pins(tmp_path)


def test_pe_read_and_backend_check(tmp_path):
    prefix = bytes.fromhex("5541574156415541545657534881ec28")
    image = _pe(tmp_path / "codex.exe", 0x2345, prefix)
    assert svc.pe_read(image, 0x2345, len(prefix)) == prefix
    with pytest.raises(ValueError, match="outside"):
        svc.pe_read(image, 0x90000, 4)
    pin = {"backend": {"sha256": svc.file_sha256(image)},
           "hooks": {name: {"rva": "0x2345", "prefix_hex": prefix.hex()}
                     for name in svc.HOOK_NAMES}}
    svc.check_backend(pin, image)
    pin["hooks"]["wss"]["prefix_hex"] = "00" * 16
    with pytest.raises(ValueError, match="wss hook entry bytes"):
        svc.check_backend(pin, image)
    with pytest.raises(ValueError, match="does not match the pinned Codex version"):
        svc.check_backend(pin, image, image_sha256="0" * 64)


def test_compile_defines_carry_every_pinned_value():
    pin = next(iter(svc.load_pins().values()))
    defines = " ".join(svc.compile_defines(pin))
    for name in svc.HOOK_NAMES:
        assert pin["hooks"][name]["rva"] in defines
    assert "-DTTRACE_GRACEFUL_LEASE=1" in defines and "-DTTRACE_NONRETRY_DENY_LAB=1" in defines
    assert "-DWSS_SUCCESS_TAG=0x20" in defines and "-DWSS_DENIED_TAG=25" in defines
    assert f'-DTTRACE_EXPECTED_HASH="{pin["backend"]["sha256"]}"' in defines


def test_source_digest_ignores_line_endings(tmp_path):
    lf, crlf = tmp_path / "lf.c", tmp_path / "crlf.c"
    lf.write_bytes(b"int a;\nint b;\n")
    crlf.write_bytes(b"int a;\r\nint b;\r\n")
    assert svc.normalized_sha256(lf) == svc.normalized_sha256(crlf)


def _source_tree(root: Path) -> None:
    (root / svc.THIRD_PARTY / "minhook/src/hde").mkdir(parents=True)
    (root / svc.GUARD_SOURCE).write_text("int guard;\n")
    (root / svc.THIRD_PARTY / "minhook/src/hook.c").write_text("int hook;\n")
    (root / svc.THIRD_PARTY / "minhook/src/hde/hde64.h").write_text("#define X 1\n")
    (root / svc.THIRD_PARTY / "README.md").write_text("not compiled\n")


def test_ensure_dll_builds_once_and_never_overwrites_a_loaded_dll(tmp_path):
    _source_tree(tmp_path)
    pin = {**next(iter(svc.load_pins().values())), "_path": tmp_path / "pin.json"}
    calls = []

    def compiler(arguments, cwd):
        calls.append(arguments)
        Path(arguments[arguments.index("-o") + 1]).write_bytes(b"MZ" + bytes(len(calls)))

    first = svc.ensure_dll(pin, root=tmp_path, compiler=compiler)
    assert first.name.startswith(svc.DLL_PREFIX) and len(calls) == 1
    assert svc.ensure_dll(pin, root=tmp_path, compiler=compiler) == first
    assert len(calls) == 1  # cached
    manifest = json.loads(first.with_suffix(".json").read_text())
    assert set(manifest["sources"]) == {svc.GUARD_SOURCE,
                                        f"{svc.THIRD_PARTY}/minhook/src/hook.c",
                                        f"{svc.THIRD_PARTY}/minhook/src/hde/hde64.h"}
    assert not any("\\" in name or ":" in name for name in manifest["sources"])

    (tmp_path / svc.GUARD_SOURCE).write_text("int guard_changed;\n")
    second = svc.ensure_dll(pin, root=tmp_path, compiler=compiler)
    assert second != first and first.exists() and len(calls) == 2
    assert list(second.parent.glob("build-*")) == []


def test_ensure_dll_rebuilds_a_tampered_dll(tmp_path):
    _source_tree(tmp_path)
    pin = {**next(iter(svc.load_pins().values())), "_path": tmp_path / "pin.json"}
    calls = []

    def compiler(arguments, cwd):
        calls.append(1)
        Path(arguments[arguments.index("-o") + 1]).write_bytes(b"MZ-good")

    dll = svc.ensure_dll(pin, root=tmp_path, compiler=compiler)
    dll.write_bytes(b"MZ-tampered")
    assert svc.ensure_dll(pin, root=tmp_path, compiler=compiler) == dll
    assert len(calls) == 2 and dll.read_bytes() == b"MZ-good"


@pytest.mark.parametrize("command, expected", [
    (r'"C:\x\codex.exe" -c features.code_mode_host=true app-server --analytics-default-enabled', True),
    (r'C:\x\codex.exe -c "forced_login_method=\"chatgpt\"" exec-server --remote https://x', False),
    (r'C:\x\codex.exe -c app-server exec', False),
    ("", False),
])
def test_only_the_local_app_server_is_a_target(command, expected):
    assert svc.is_local_app_server(command) is expected


def test_decision_log_reports_rules_of_denied_items():
    request = SimpleNamespace(kind="model.request", request_id="1-3", protocol="http",
                              payload_utf8="x" * 2048)
    decision = SimpleNamespace(decision="deny", reason="SENSITIVE_OR_AMBIGUOUS_CONTENT")
    records = [{"actionable_decision": "ALLOW", "matched_rule_ids": ["ENTROPY_TOKEN"]},
               {"actionable_decision": "BLOCK", "matched_rule_ids": ["GITHUB_TOKEN"]},
               {"actionable_decision": "BLOCK", "matched_rule_ids": []}]
    results = {"1-3": SimpleNamespace(records=records)}
    engine = SimpleNamespace(policy=SimpleNamespace(version="v"), concurrent_safe=True,
                             evaluate=lambda r: (decision, {"row": 1}))
    seen = []
    log = svc._DecisionLog(engine, results, lambda *args: seen.append(args))
    assert log.evaluate(request) == (decision, {"row": 1})
    assert log.concurrent_safe is True and log.policy.version == "v"
    assert seen[0][2] == ["GITHUB_TOKEN"] and "1-3" not in results


def test_controller_log_line_is_concise():
    lines = []
    status = svc.BackendStatus(42, 7)
    worker = svc.BackendController({"pid": 42, "creation_filetime": 7}, Path("x.dll"),
                                   None, {}, Path("."), status, lines.append)
    request = SimpleNamespace(protocol="http", payload_utf8="a" * 4096)
    worker._decision(request, SimpleNamespace(decision="deny", reason="R"), ["CN_ID"], 12.3)
    worker._decision(request, SimpleNamespace(decision="allow", reason="OK"), [], 4.0)
    assert lines == ["[Codex 42] 拒绝  http 4 KB  12 ms  CN_ID",
                     "[Codex 42] 放行  http 4 KB  4 ms"]
    assert (status.requests, status.allowed, status.denied) == (2, 1, 1)


def test_unsupported_backend_is_reported_not_attached(tmp_path, monkeypatch):
    supervisor = svc.Supervisor(state_dir=tmp_path, log=lambda message: None)
    supervisor.user_sid = "S-1-5-21-1"
    monkeypatch.setattr(svc, "process_details", lambda pid: {
        "pid": pid, "creation_filetime": 9, "image_path": str(tmp_path / "codex.exe"),
        "command_line": r"C:\x\codex.exe app-server", "user_sid": "S-1-5-21-1"})
    monkeypatch.setattr(supervisor.hashes, "sha256", lambda path: "f" * 64)
    supervisor._consider(77)
    status = supervisor.backends[(77, 9)]
    assert status.state == "UNSUPPORTED_VERSION" and not supervisor.controllers


def test_other_users_and_exec_server_are_ignored(tmp_path, monkeypatch):
    supervisor = svc.Supervisor(state_dir=tmp_path, log=lambda message: None)
    supervisor.user_sid = "S-1-5-21-1"
    rows = {1: {"pid": 1, "creation_filetime": 1, "image_path": "a",
                "command_line": r"C:\x\codex.exe app-server", "user_sid": "S-1-5-21-2"},
            2: {"pid": 2, "creation_filetime": 1, "image_path": "a",
                "command_line": r"C:\x\codex.exe exec-server --remote x",
                "user_sid": "S-1-5-21-1"}}
    monkeypatch.setattr(svc, "process_details", rows.get)
    supervisor._consider(1)
    supervisor._consider(2)
    supervisor._consider(3)
    assert supervisor.backends == {}
