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


@pytest.mark.parametrize("marker", [
    {"status": "candidate_lab_only"},
    {"production_ready": False},
])
def test_candidate_pin_cannot_be_loaded_by_supervisor(tmp_path, marker):
    path = _pin(tmp_path, **marker)
    with pytest.raises(ValueError, match="candidate pin cannot be loaded"):
        svc.load_pins(tmp_path)
    # Static pin validation remains available for a manual isolated build.
    assert svc._validate_pin(json.loads(path.read_text(encoding="utf-8")), path)[
        "codex_desktop_version"] == "26.1103.3517.0"


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
    assert "-DAPI_ERROR_DENIED_TAG=25" in defines
    assert f'-DTTRACE_EXPECTED_HASH="{pin["backend"]["sha256"]}"' in defines


def test_new_pin_can_select_a_verified_error_denial_tag(tmp_path):
    old = next(iter(svc.load_pins().values()))
    new_abi = {**old["abi"], "api_error_denied_tag": 29}
    _pin(tmp_path, abi=new_abi)
    pin = next(iter(svc.load_pins(tmp_path).values()))
    assert pin["abi"]["api_error_denied_tag"] == 29
    assert "-DAPI_ERROR_DENIED_TAG=29" in svc.compile_defines(pin)


@pytest.mark.parametrize("invalid", ["29", -1, 0, 256, True])
def test_invalid_error_denial_tag_is_rejected(tmp_path, invalid):
    old = next(iter(svc.load_pins().values()))
    _pin(tmp_path, abi={**old["abi"], "api_error_denied_tag": invalid})
    with pytest.raises(ValueError, match="invalid desktop guard pin"):
        svc.load_pins(tmp_path)


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
    monkeypatch.setattr(supervisor.hashes, "code_sha256", lambda path: "e" * 64)
    monkeypatch.setattr(svc, "installed_packages", lambda: {})
    supervisor._consider(77)
    status = supervisor.backends[(77, 9)]
    assert status.state == "UNSUPPORTED_VERSION" and not supervisor.controllers
    assert "代码与已验证版本不同" in status.detail
    assert not list((tmp_path / "pins").glob("*.json"))


def _signed_pe(path: Path, code: bytes, checksum: int, signature: bytes) -> Path:
    """PE32+ with a .text payload, a CheckSum and a trailing certificate table."""
    data = bytearray(0x400)
    pe = 0x80
    data[0x3C:0x40] = struct.pack("<I", pe)
    data[pe:pe + 4] = b"PE\0\0"
    struct.pack_into("<HH", data, pe + 4, 0x8664, 1)
    struct.pack_into("<H", data, pe + 20, 0xF0)
    optional = pe + 24
    struct.pack_into("<H", data, optional, 0x20B)
    struct.pack_into("<I", data, optional + 64, checksum)
    body = bytes(data) + code
    struct.pack_into("<II", data, optional + 112 + 32, len(body), len(signature))
    path.write_bytes(bytes(data) + code + signature)
    return path


def test_code_digest_ignores_signature_and_checksum_only(tmp_path):
    base = _signed_pe(tmp_path / "a.exe", b"\x90" * 64, 0x1111, b"SIG-A" * 10)
    resigned = _signed_pe(tmp_path / "b.exe", b"\x90" * 64, 0x2222, b"SIG-B-LONGER" * 9)
    patched = _signed_pe(tmp_path / "c.exe", b"\x90" * 63 + b"\xcc", 0x1111, b"SIG-A" * 10)
    assert svc.file_sha256(base) != svc.file_sha256(resigned)
    assert svc.code_sha256(base) == svc.code_sha256(resigned)
    assert svc.code_sha256(base) != svc.code_sha256(patched)
    with pytest.raises(ValueError, match="PE32"):
        svc.code_sha256(_pe(tmp_path / "pe32.exe", 0x1000, b"\0" * 4))


def test_repository_pin_carries_the_validated_code_digest():
    pin = next(iter(svc.load_pins().values()))
    assert pin["backend"]["code_sha256"] == (
        "583ed1f42412daf9ac61a74788f077bfe8d178a1f4acd6a39bdd4e171fa6ba4f")


def test_derived_pin_reuses_hooks_and_is_loaded_from_the_local_directory(tmp_path):
    base = next(iter(svc.load_pins().values()))
    local = tmp_path / "pins"
    derived = svc.derive_pin(base, "a" * 64, base["backend"]["code_sha256"],
                             "26.1103.4239.0", local, "OpenAI.Codex_26.1103.4239.0_x64__x")
    assert derived["hooks"] == base["hooks"] and derived["abi"] == base["abi"]
    assert derived["derived_from"]["method"] == "identical_code_resigned"
    pins = svc.load_pins(svc.PIN_DIR, local)
    assert pins["a" * 64]["codex_desktop_version"] == "26.1103.4239.0"
    assert base["backend"]["sha256"] in pins
    with pytest.raises(ValueError, match="code digest differs"):
        svc.derive_pin(base, "b" * 64, "c" * 64, "x", local)


def test_package_version_from_full_name():
    assert svc.package_version("OpenAI.Codex_26.1103.4239.0_x64__2p2nqsd0c76g0") == "26.1103.4239.0"


def test_adapt_known_resigned_and_changed_backends(tmp_path, monkeypatch):
    lines = []
    supervisor = svc.Supervisor(state_dir=tmp_path, log=lines.append)
    base = next(iter(supervisor.pins.values()))
    built = []
    monkeypatch.setattr(svc, "ensure_dll", lambda pin, image: built.append(pin) or Path("g.dll"))
    monkeypatch.setattr(svc, "installed_packages", lambda: {})
    monkeypatch.setattr(supervisor, "_backup", lambda pin, image: None)
    hashes = {"known.exe": (base["backend"]["sha256"], base["backend"]["code_sha256"]),
              "resigned.exe": ("1" * 64, base["backend"]["code_sha256"]),
              "changed.exe": ("2" * 64, "3" * 64)}
    monkeypatch.setattr(supervisor.hashes, "sha256", lambda path: hashes[Path(path).name][0])
    monkeypatch.setattr(supervisor.hashes, "code_sha256", lambda path: hashes[Path(path).name][1])

    assert supervisor.adapt(Path("known.exe")) is base and lines == []
    derived = supervisor.adapt(Path("resigned.exe"), "OpenAI.Codex_26.1103.4239.0_x64__x")
    assert derived["codex_desktop_version"] == "26.1103.4239.0"
    assert "已自动适配" in lines[-1] and "1" * 64 in supervisor.pins
    assert supervisor.adapt(Path("changed.exe")) is None
    assert [pin["backend"]["sha256"] for pin in built] == [base["backend"]["sha256"], "1" * 64]
    # The derived pin survives a restart of the guard.
    again = svc.Supervisor(state_dir=tmp_path, log=lambda message: None)
    assert "1" * 64 in again.pins
    assert "26.1103.4239.0" in again.state()["adapted_versions"]


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


def test_backup_keeps_the_newest_three_supported_backends(tmp_path):
    supervisor = svc.Supervisor(state_dir=tmp_path / "state", log=lambda message: None)
    base = next(iter(supervisor.pins.values()))
    image = tmp_path / "codex.exe"
    image.write_bytes(b"MZ backend")
    for index in range(5):
        pin = {**base, "codex_desktop_version": f"26.1.{index}",
               "backend": {**base["backend"], "sha256": f"{index:x}" * 64}}
        supervisor._backup(pin, image)
        supervisor._backup(pin, image)  # a second call copies nothing new
    kept = sorted(path.name for path in (tmp_path / "state" / "backends").iterdir())
    assert len(kept) == 3
    for name in kept:
        folder = tmp_path / "state" / "backends" / name
        assert (folder / "codex.exe").read_bytes() == b"MZ backend"
        assert "_path" not in json.loads((folder / "pin.json").read_text(encoding="utf-8"))
