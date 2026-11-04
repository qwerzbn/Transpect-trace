"""Check the fixed backend accepts the safe DeepSeek catalog without a real API."""
from __future__ import annotations

from contextlib import contextmanager
import json
from pathlib import Path
import shutil
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import probe_desktop_backend_lab as lab  # noqa: E402


CATALOG = ROOT / "deploy/guard/desktop-deepseek-v4-pro-models.json"
SYNTHETIC_TOKEN = "LOCAL_FAKE_DEEPSEEK_KEY_FOR_SINK"


def test_catalog_has_one_text_model_and_no_vendor_instruction_template():
    data = json.loads(CATALOG.read_text(encoding="utf-8"))
    assert len(data["models"]) == 1
    model = data["models"][0]
    assert model["slug"] == "deepseek-v4-pro"
    assert model["input_modalities"] == ["text"]
    assert "model_messages" not in model
    assert "instructions_template" not in model


def probe_custom_model(monkeypatch, *, command_auth: bool = False) -> tuple[dict, dict]:
    observed: dict = {}

    def configure(home: Path, port: int) -> None:
        home.mkdir()
        catalog = home / "models.json"
        shutil.copyfile(CATALOG, catalog)
        auth_config = ""
        if command_auth:
            helper = home / "synthetic_auth.py"
            helper.write_text(f'print("{SYNTHETIC_TOKEN}")\n', encoding="utf-8")
            auth_config = (
                '[model_providers.ttrace_local_probe.auth]\n'
                f'command = "{Path(sys.executable).as_posix()}"\n'
                f'args = ["{helper.as_posix()}"]\n'
            )
        auth_setting = '' if command_auth else 'requires_openai_auth = false\n'
        (home / "config.toml").write_text(
            'model = "deepseek-v4-pro"\n'
            'model_provider = "ttrace_local_probe"\n'
            'web_search = "disabled"\n'
            f'model_catalog_json = "{catalog.as_posix()}"\n'
            '[model_providers.ttrace_local_probe]\n'
            'name = "Local non-forwarding probe"\n'
            f'base_url = "http://127.0.0.1:{port}/v1"\n'
            'wire_api = "responses"\n'
            f'{auth_setting}'
            'request_max_retries = 0\n'
            'stream_max_retries = 0\n'
            'supports_websockets = false\n'
            + auth_config,
            encoding="utf-8",
        )

    request_original = lab._request

    def request(process, identifier: int, method: str, params: dict) -> None:
        if method == "thread/start":
            params = {**params, "model": "deepseek-v4-pro"}
        request_original(process, identifier, method, params)

    monkeypatch.setattr(lab, "configure", configure)
    monkeypatch.setattr(lab, "_request", request)
    if command_auth:
        original_handler = lab._SinkHandler

        class AuthCheckingHandler(original_handler):
            def do_POST(self) -> None:
                self.server.synthetic_auth_ok = (
                    self.headers.get("Authorization") == f"Bearer {SYNTHETIC_TOKEN}"
                )
                super().do_POST()

        monkeypatch.setattr(lab, "_SinkHandler", AuthCheckingHandler)
        original_local_sink = lab.local_sink

        @contextmanager
        def observed_sink(marker):
            with original_local_sink(marker) as server:
                observed["server"] = server
                yield server

        monkeypatch.setattr(lab, "local_sink", observed_sink)

    report = lab.probe(lab.BACKEND, lab.ADAPTER, with_frida=False)
    return report, observed


@pytest.mark.skipif(not lab.BACKEND.is_file(), reason="pinned desktop backend not archived")
def test_fixed_backend_sends_custom_model_prompt_to_non_forwarding_sink(monkeypatch):
    report, _observed = probe_custom_model(monkeypatch)
    assert report["handshake"] == ["initialized", "thread/start", "turn/start"]
    assert not [error for error in report["errors"] if error != "temp_cleanup_incomplete"]
    assert report["sink"]["requests"] == 1
    assert report["sink"]["marker_in_body"] is True
    assert report["sink"]["paths"] == ["responses"]


@pytest.mark.skipif(not lab.BACKEND.is_file(), reason="pinned desktop backend not archived")
def test_fixed_backend_accepts_synthetic_command_auth_without_real_key(monkeypatch):
    report, observed = probe_custom_model(monkeypatch, command_auth=True)
    assert report["handshake"] == ["initialized", "thread/start", "turn/start"]
    assert not [error for error in report["errors"] if error != "temp_cleanup_incomplete"]
    assert report["sink"]["requests"] == 1
    assert report["sink"]["marker_in_body"] is True
    assert observed["server"].synthetic_auth_ok is True
