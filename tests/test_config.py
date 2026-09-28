from __future__ import annotations

from pathlib import Path

from transpect_trace.config import load_project_env, provider_api_key


def test_generic_dotenv_names_are_loaded_without_overriding_environment(
    tmp_path: Path, monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    for name in ("API_KEY", "BASE_URL", "MODEL_ID", "DEEPSEEK_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    (tmp_path / ".env").write_text(
        "API_KEY=fake-test-key\nBASE_URL=https://example.invalid\nMODEL_ID=test-model\n",
        encoding="utf-8",
    )

    loaded = load_project_env()

    assert loaded == (tmp_path / ".env").resolve()
    assert provider_api_key("deepseek") == "fake-test-key"

    monkeypatch.setenv("DEEPSEEK_API_KEY", "explicit-key")
    load_project_env()
    assert provider_api_key("deepseek") == "explicit-key"
