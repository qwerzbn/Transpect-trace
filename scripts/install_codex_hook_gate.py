"""Install, inspect or remove the DLP gate in a Codex hooks layer.

Two layers are supported:

* `user` writes `<CODEX_HOME>/hooks.json`. Codex asks the signed-in user to
  review and trust these hooks before it runs them; an untrusted hook is
  silently skipped, so an install is not yet an active gate.
* `managed` writes `%ProgramData%\\OpenAI\\Codex\\requirements.toml`, the layer
  the client documents as enforced. It needs an administrator and applies to
  every Codex session on the machine.

  **Not working on the pinned build.** On `codex-cli 0.166.0-alpha.6` the file
  is read -- an unsupported key there is reported as
  ``requirements (...\\requirements.toml): `model` is ignored`` -- and
  `hooks.windows_managed_dir` is in the client's own requirements schema, yet
  pointing it at a hooks directory loaded no hook and emitted no diagnostic.
  Treat this layer as unvalidated until that is resolved; the `user` layer plus
  the trust prompt is the path verified end to end.

The command string is validated against the client's tokenizer: Codex splits a
hook command on whitespace and does not honor quotes, so no path may contain a
space.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from transpect_trace.protect.codex_hook_gate import (  # noqa: E402
    CONFIG_ENV, CONFIG_SCHEMA, ENFORCED_EVENTS, MODES, OBSERVED_EVENTS,
)
from transpect_trace.protect.codex_gate_service import PIPE_PREFIX  # noqa: E402

GATE_MARKER = "transpect-codex-dlp-gate"
# Only events the gate answers. `PreModelRequest` is observe-only in this
# client, so it is registered for evidence, never as a control, and runs async
# so it adds no latency to a request it cannot stop.
INSTALLED_EVENTS = tuple(sorted(ENFORCED_EVENTS)) + ("PreModelRequest",)
ASYNC_EVENTS = frozenset(("PreModelRequest",))
_TOML_EVENT_KEY = {
    "UserPromptSubmit": "user_prompt_submit",
    "PreToolUse": "pre_tool_use",
    "PostToolUse": "post_tool_use",
    "PreModelRequest": "pre_model_request",
}
MANIFEST_NAME = "gate-manifest.json"
MANIFEST_SCHEMA = "transpect.codex-hook-gate.manifest/1.0"


def _handler(event: str, command: str) -> dict:
    handler = {"type": "command", "command": command}
    if event in ASYNC_EVENTS:
        handler["async"] = True
    return handler


def build_command(python: Path, entry: Path, config: Path,
                  client: Path | None = None) -> str:
    """The hook command line. With `client`, Codex runs the native forwarder:
    `client.exe <pipe> <python> <entry> <config>`; the last three are its
    fail-closed fallback when the resident service is not answering."""
    parts = [str(python), str(entry), str(config)]
    if client is not None:
        from transpect_trace.protect.codex_gate_service import pipe_name
        parts = [str(client), pipe_name(config)] + parts
    for part in parts:
        if " " in part or "\t" in part:
            raise ValueError(
                f"Codex cannot quote hook command tokens; this path has a space: {part}")
        if not part.startswith(PIPE_PREFIX) and not Path(part).exists():
            raise ValueError(f"hook command path does not exist: {part}")
    return " ".join(parts)


def write_gate_config(directory: Path, mode: str, registration: Path | None,
                      *, enforced_categories: list[str] | None = None,
                      advisory_rule_ids: list[str] | None = None,
                      codex_home: Path | None = None,
                      review_override_ttl_seconds: int | None = None,
                      egress_allowed_hosts: list[str] | None = None) -> Path:
    if mode not in MODES:
        raise ValueError("mode must be enforce or observe")
    directory.mkdir(parents=True, exist_ok=True)
    config = {
        "schema": CONFIG_SCHEMA,
        "mode": mode,
        "archive_directory": str(directory / "encrypted-archive"),
        "audit_file": str(directory / "audit.jsonl"),
    }
    if registration is not None:
        config["registration_directory"] = str(registration.resolve(strict=True))
    if enforced_categories is not None:
        config["enforced_categories"] = sorted(set(enforced_categories))
    if advisory_rule_ids is not None:
        config["advisory_rule_ids"] = sorted(set(advisory_rule_ids))
    if review_override_ttl_seconds is not None:
        config["review_override_ttl_seconds"] = review_override_ttl_seconds
    if egress_allowed_hosts is not None:
        config["egress_allowed_hosts"] = sorted(set(egress_allowed_hosts))
    # Editing any of these switches the gate off for later turns, so an agent
    # tool call that names them is denied as GATE_TAMPER.
    protected = [str(directory)]
    if codex_home is not None:
        protected += [str(codex_home / "hooks.json"), str(codex_home / "config.toml")]
    config["protected_paths"] = sorted(set(protected))
    path = directory / "gate-config.json"
    path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    return path


def gate_source_files(root: Path = ROOT) -> list[Path]:
    """Every file the hook process imports from this checkout."""
    protect = root / "src" / "transpect_trace" / "protect"
    files = [root / "scripts" / "codex_hook_gate.py",
             root / "src" / "transpect_trace" / "__init__.py"]
    files += sorted(protect.glob("*.py"))
    return [path for path in files if path.is_file()]


def write_manifest(directory: Path, command: str, files: list[Path]) -> Path:
    """Record what was installed, so a later health check can detect drift."""
    entries = []
    for path in files:
        entries.append({"path": str(path.resolve()),
                        "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    document = {"schema": MANIFEST_SCHEMA, "command": command,
                "command_sha256": hashlib.sha256(command.encode("utf-8")).hexdigest(),
                "events": list(INSTALLED_EVENTS), "files": entries}
    path = directory / MANIFEST_NAME
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    return path


def user_hooks_document(existing: dict | None, command: str) -> dict:
    """Keep unrelated hooks; replace only groups this installer owns."""
    document = dict(existing or {})
    events = dict(document.get("hooks") or {})
    for event in INSTALLED_EVENTS:
        groups = [group for group in events.get(event, [])
                  if not (isinstance(group, dict)
                          and group.get("description") == GATE_MARKER)]
        groups.append({"description": GATE_MARKER,
                       "hooks": [_handler(event, command)]})
        events[event] = groups
    document["hooks"] = events
    return document


def requirements_hooks_toml(managed_dir: Path) -> str:
    """Point the enforced layer at an administrator-owned hooks directory.

    `requirements.toml` does not hold the event map itself: its `[hooks]` table
    takes `windows_managed_dir`, and the client loads `hooks.json` from there as
    a required managed layer. Keeping the map in a separate directory is what
    lets an administrator ACL the gate without also owning every other
    requirement in the file.
    """
    return "\n".join([
        "# Managed Codex requirements written by scripts/install_codex_hook_gate.py.",
        "# Hooks loaded through this layer are enforced: the signed-in user is not",
        "# asked to trust them and cannot skip them from CODEX_HOME.",
        "",
        "[hooks]",
        f'windows_managed_dir = "{str(managed_dir).replace(chr(92), "/")}"',
        "",
    ])


def install_user_layer(codex_home: Path, command: str, *, dry_run: bool) -> dict:
    path = codex_home / "hooks.json"
    existing = None
    if path.exists():
        existing = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(existing, dict):
            raise ValueError("existing hooks.json is not an object")
    document = user_hooks_document(existing, command)
    body = json.dumps(document, indent=2, ensure_ascii=False) + "\n"
    if not dry_run:
        codex_home.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
    return {"layer": "user", "path": str(path), "events": list(INSTALLED_EVENTS),
            "written": not dry_run, "preview": body}


def install_managed_layer(directory: Path, command: str, *, dry_run: bool,
                          managed_hooks_dir: Path | None = None) -> dict:
    path = directory / "requirements.toml"
    if path.exists():
        raise ValueError(
            f"{path} already exists; merge it by hand so no managed setting is lost")
    hooks_dir = managed_hooks_dir or (directory / "managed-hooks")
    requirements = requirements_hooks_toml(hooks_dir)
    hooks = json.dumps(user_hooks_document(None, command), indent=2,
                       ensure_ascii=False) + "\n"
    if not dry_run:
        directory.mkdir(parents=True, exist_ok=True)
        hooks_dir.mkdir(parents=True, exist_ok=True)
        (hooks_dir / "hooks.json").write_text(hooks, encoding="utf-8")
        path.write_text(requirements, encoding="utf-8")
    return {"layer": "managed", "path": str(path),
            "managed_hooks_file": str(hooks_dir / "hooks.json"),
            "events": list(INSTALLED_EVENTS), "written": not dry_run,
            "preview": requirements + "\n--- managed hooks.json ---\n" + hooks}


def remove_user_layer(codex_home: Path, *, dry_run: bool) -> dict:
    path = codex_home / "hooks.json"
    if not path.exists():
        return {"layer": "user", "path": str(path), "removed": 0}
    document = json.loads(path.read_text(encoding="utf-8"))
    events = dict(document.get("hooks") or {})
    removed = 0
    for event, groups in list(events.items()):
        kept = [group for group in groups
                if not (isinstance(group, dict)
                        and group.get("description") == GATE_MARKER)]
        removed += len(groups) - len(kept)
        if kept:
            events[event] = kept
        else:
            events.pop(event)
    document["hooks"] = events
    if not dry_run:
        if events or set(document) - {"hooks"}:
            path.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n",
                            encoding="utf-8")
        else:
            path.unlink()
    return {"layer": "user", "path": str(path), "removed": removed,
            "written": not dry_run}


SERVICE_TASK = "Transpect-Codex-Gate-Service"


def register_service_task(python: Path, config: Path, *, dry_run: bool) -> dict:
    """A per-user logon task (Limited, Interactive) that keeps the service up.

    `pythonw.exe` when present, so no console window stays open. The task
    restarts the service if it exits; a stopped service is still fail-closed
    because the native client falls back to the per-event gate.
    """
    runner = python.with_name("pythonw.exe")
    runner = runner if runner.is_file() else python
    arguments = f'-m transpect_trace.protect.codex_gate_service "{config}"'
    script = f"""
$ErrorActionPreference = 'Stop'
$action = New-ScheduledTaskAction -Execute '{runner}' -Argument '{arguments}' -WorkingDirectory '{ROOT / "src"}'
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$principal = New-ScheduledTaskPrincipal -UserId ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName '{SERVICE_TASK}' -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description 'Transpect Codex DLP gate resident service' -Force | Out-Null
Start-ScheduledTask -TaskName '{SERVICE_TASK}'
"""
    if dry_run:
        return {"task": SERVICE_TASK, "registered": False, "script": script}
    import subprocess
    subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                   check=True, capture_output=True, text=True, timeout=120)
    return {"task": SERVICE_TASK, "registered": True, "runner": str(runner)}


def default_codex_home() -> Path:
    return Path(os.environ.get("CODEX_HOME") or (Path.home() / ".codex"))


def default_managed_directory() -> Path:
    return Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "OpenAI" / "Codex"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--layer", choices=("user", "managed"), default="user")
    parser.add_argument("--mode", choices=sorted(MODES), default="enforce")
    parser.add_argument("--gate-directory", type=Path,
                        default=ROOT / "runs" / "codex-hook-gate")
    parser.add_argument("--registration", type=Path, default=None,
                        help="private EDM/fingerprint registration directory")
    parser.add_argument("--codex-home", type=Path, default=None)
    parser.add_argument("--managed-directory", type=Path, default=None)
    parser.add_argument("--managed-hooks-directory", type=Path, default=None,
                        help="administrator-owned directory holding the enforced "
                             "hooks.json; defaults to <managed>/managed-hooks")
    parser.add_argument("--python", type=Path, default=Path(sys.executable))
    parser.add_argument("--client", choices=("python", "native"), default="python",
                        help="native: Codex runs build/codex-gate-client/codex_gate_client.exe, "
                             "which asks the resident service and falls back to the Python gate")
    parser.add_argument("--register-service", action="store_true",
                        help="register a per-user logon task that runs the resident service")
    parser.add_argument("--review-override-ttl", type=int, default=None,
                        help="seconds a REVIEW approval code stays valid; 0 disables")
    parser.add_argument("--remove", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    codex_home = (args.codex_home or default_codex_home()).resolve()
    if args.remove:
        if args.layer != "user":
            raise SystemExit("remove the managed layer by deleting requirements.toml "
                             "as an administrator")
        result = remove_user_layer(codex_home, dry_run=args.dry_run)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return

    gate_directory = args.gate_directory.resolve()
    config = write_gate_config(gate_directory, args.mode, args.registration,
                               codex_home=codex_home,
                               review_override_ttl_seconds=args.review_override_ttl)
    client = None
    if args.client == "native":
        client = (ROOT / "build" / "codex-gate-client" / "codex_gate_client.exe")
        if not client.is_file():
            raise SystemExit("build the client first: "
                             "uv run --no-sync python scripts/build_codex_gate_client.py")
        client = client.resolve()
    command = build_command(args.python.resolve(strict=True),
                            (ROOT / "scripts" / "codex_hook_gate.py").resolve(strict=True),
                            config, client)
    if args.layer == "user":
        result = install_user_layer(codex_home, command, dry_run=args.dry_run)
    else:
        directory = (args.managed_directory or default_managed_directory()).resolve()
        hooks_dir = (args.managed_hooks_directory.resolve()
                     if args.managed_hooks_directory else None)
        result = install_managed_layer(directory, command, dry_run=args.dry_run,
                                       managed_hooks_dir=hooks_dir)
    result.update(mode=args.mode, command=command, gate_config=str(config),
                  enforced_events=sorted(ENFORCED_EVENTS),
                  observed_events=sorted(OBSERVED_EVENTS),
                  config_env=CONFIG_ENV)
    if not args.dry_run:
        files = gate_source_files() + ([client] if client else [])
        result["manifest"] = str(write_manifest(gate_directory, command, files))
    if args.register_service:
        result["service_task"] = register_service_task(args.python.resolve(strict=True), config,
                                                       dry_run=args.dry_run)
    preview = result.pop("preview")
    print(json.dumps(result, indent=2, ensure_ascii=False))
    print("\n--- file content ---\n" + preview)
    if args.layer == "user" and not args.dry_run:
        print("Restart Codex and accept the hook review prompt; an untrusted hook "
              "is skipped without an error.")


if __name__ == "__main__":
    main()
