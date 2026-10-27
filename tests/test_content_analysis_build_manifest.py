import hashlib
import importlib.util
import json
from pathlib import Path
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]


def build_module():
    path = ROOT / "scripts/build_content_analysis_agent.py"
    spec = importlib.util.spec_from_file_location("build_content_analysis_agent", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.path.insert(0, str(path.parent))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(path.parent))
    return module


def test_sdk_manifest_is_exact_and_records_license_and_archive():
    value = json.loads(
        (ROOT / "patches/content-analysis-sdk/manifest.json").read_text(encoding="utf-8")
    )
    assert value["schema"] == "transpect.vendor.content-analysis-sdk/1.0"
    assert value["commit"] == "2a8191af30a4d1f591e2f758e595bdeea139e93a"
    assert value["archive_sha256"] == "53823109c5e44c51dfcf64640f5a4eaef3ab27745488515d5bafcb885e42e659"
    assert value["license"] == "BSD-3-Clause"
    assert value["source_sha256"]["LICENSE"] == value["license_sha256"]
    assert value["toolchain"] == {
        "vcpkg_commit": "817892b0ecbc6af994dd6df999c73faf795adbf2",
        "triplet": "x64-windows",
        "packages": ["protobuf"],
    }
    assert "proto/content_analysis/sdk/analysis.proto" in value["source_sha256"]
    assert len(value["source_sha256"]) >= 25
    assert "browser/src/client_win.cc" in value["source_sha256"]


def test_sdk_verifier_rejects_modified_source(monkeypatch, tmp_path):
    module = build_module()
    source = tmp_path / "source.cc"
    source.write_bytes(b"known source\n")
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    pin = {"commit": "a" * 40, "source_sha256": {"source.cc": digest}}
    monkeypatch.setattr(module, "_is_git_worktree", lambda _: True)
    monkeypatch.setattr(
        module,
        "_git",
        lambda _root, *args: "a" * 40 if args[:2] == ("rev-parse", "HEAD") else "",
    )
    assert module.verify_sdk_checkout(tmp_path, pin) == {"source.cc": digest}
    source.write_bytes(b"modified\n")
    with pytest.raises(RuntimeError, match="source hash mismatch"):
        module.verify_sdk_checkout(tmp_path, pin)


def test_policy_examples_are_cloud_only_fail_closed_prototypes():
    expected = {
        "chrome-content-file-policy.example.json": "OnFileAttachedEnterpriseConnector",
        "chrome-content-bulk-policy.example.json": "OnBulkDataEntryEnterpriseConnector",
    }
    for name, policy_name in expected.items():
        value = json.loads((ROOT / "deploy/protect" / name).read_text(encoding="utf-8"))
        assert value["delivery"] == "chrome_enterprise_core_cloud_only"
        assert value["prototype_only"] is True
        assert value["policy_name"] == policy_name
        assert "registry import" in " ".join(value["notes"]).lower()
        connector = value["value"][0]
        assert connector["service_provider"] == "local_user_agent"
        assert connector["block_until_verdict"] == 1
        assert connector["default_action"] == "block"
        assert connector["enable"] == [
            {"url_list": ["https://chatgpt.com/*"], "tags": ["dlp"]}
        ]
    bulk = json.loads(
        (ROOT / "deploy/protect/chrome-content-bulk-policy.example.json").read_text()
    )
    assert bulk["value"][0]["minimum_data_size"] == 1


def test_build_script_has_read_only_preflight_option():
    module = build_module()
    source = (ROOT / "scripts/build_content_analysis_agent.py").read_text(
        encoding="utf-8"
    )
    assert '"--check"' in source
    assert "if args.check:" in source
