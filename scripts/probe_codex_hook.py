"""Run the fixed official Codex against a synthetic TLS origin with research hooks.

This intentionally captures synthetic request bodies; it never attaches to the
desktop app-server or the current chat, and it is not a production protection tool.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import shutil
import threading
import time
from uuid import uuid4

from probe_codex_tls import Origin, certificate

EXPECTED_HASH = "d13914ced6c7af174d8d638db938284231227312104b06a25e9608c632a7daec"


def experiment(binary: Path, root: Path, transport: str, rva: int | None, action: str = "observe") -> dict:
    import frida

    root.mkdir(parents=True, exist_ok=False)
    home, workspace = root / "codex-home", root / "workspace"
    home.mkdir(); workspace.mkdir()
    marker = f"TRANSPECT_GUARD_PROBE_{uuid4().hex}"
    cert, key, ca = certificate(root)
    origin = Origin(root, cert, key, marker.encode())
    origin.thread.start()
    config = ('model_provider = "guard_probe"\napproval_policy = "never"\nsandbox_mode = "read-only"\n'
              '[features]\nplugins = false\napps = false\n'
              '[model_providers.guard_probe]\nname = "Guard test origin"\n'
              f'base_url = "https://localhost:{origin.port}"\nwire_api = "responses"\n'
              'requires_openai_auth = false\nrequest_max_retries = 0\nstream_max_retries = 0\n'
              f'supports_websockets = {str(transport == "wss").lower()}\n')
    (home / "config.toml").write_text(config)
    excluded = {"CODEX_HOME", "CODEX_CA_CERTIFICATE", "SSL_CERT_FILE", "SSLKEYLOGFILE", "RUST_LOG",
                "OPENAI_API_KEY", "API_KEY", "DEEPSEEK_API_KEY", "ANTHROPIC_API_KEY",
                "OPENAI_BASE_URL", "CODEX_API_KEY", "CHATGPT_BASE_URL", "TRANSPECT_MODEL_API_KEY"}
    env = {k: v for k, v in os.environ.items() if k.upper() not in excluded and "PROXY" not in k.upper()}
    env.update(CODEX_HOME=str(home), CODEX_CA_CERTIFICATE=str(ca),
               NO_PROXY="*", HTTP_PROXY="", HTTPS_PROXY="", ALL_PROXY="", RUST_LOG="warn")
    argv = [str(binary), "exec", "--json", "--ephemeral", "--skip-git-repo-check",
            "--model", "gpt-probe", "--cd", str(workspace),
            f"Do not run tools. Reply OK. Synthetic marker: {marker}"]
    device = frida.get_local_device()
    finished, ready = threading.Event(), threading.Event()
    records: list[dict] = []
    lock = threading.Lock()
    output_files = {1: (root / "client.stdout.jsonl").open("wb"),
                    2: (root / "client.stderr.log").open("wb")}
    pid = None; completed = False

    def output(process_id, fd, data):
        if process_id == pid and fd in output_files:
            output_files[fd].write(data)

    def message(value, data):
        row = value.get("payload", value)
        row["observed_monotonic_ns"] = time.monotonic_ns()
        with lock:
            records.append(row)
        if row.get("kind") == "probe.ready":
            ready.set()

    device.on("output", output)
    try:
        pid = device.spawn(argv, env=env, cwd=str(workspace), stdio="pipe")
        session = device.attach(pid)
        session.on("detached", lambda *args: finished.set())
        script_text = Path("deploy/guard/frida_probe.js").read_text()
        script = session.create_script("const PROBE_OPTIONS = " + json.dumps({"candidate_rva": rva,
                                      "synthetic_input_null": True, "action": action,
                                      "synthetic_marker": marker}) + ";\n" + script_text)
        script.on("message", message)
        script.load()
        if not ready.wait(10):
            raise RuntimeError("Research hook did not become ready; child remains suspended")
        device.resume(pid)
        completed = finished.wait(35)
        if not completed:
            device.kill(pid)  # Cleanup only this synthetic child; not a DLP action.
            finished.wait(3)
    finally:
        if pid is not None and not finished.is_set():
            try: device.kill(pid)
            except Exception: pass
        device.off("output", output)
        for handle in output_files.values(): handle.close()
        origin.stop.set(); origin.thread.join(timeout=15); origin.listener.close()
    (root / "research-events.jsonl").write_text("".join(json.dumps(r) + "\n" for r in records))
    payloads = [r for r in records if r.get("kind") == "outbound.payload"]
    matches = [r for r in payloads if marker in r.get("payload", "")]
    summaries = []
    for row in matches:
        try:
            parsed = json.loads(row["payload"])
            summaries.append({"sequence": row["sequence"], "valid_json": True,
                              "type": parsed.get("type"), "bytes": row["bytes"],
                              "before_later_network_event": any(r.get("kind") == "network.send" and
                                     r["sequence"] > row["sequence"] for r in records)})
        except json.JSONDecodeError:
            summaries.append({"sequence": row["sequence"], "valid_json": False})
    result = {"transport": transport, "synthetic_only": True, "pid": pid, "action": action,
              "candidate_rva": rva, "event_counts": dict(Counter(r.get("kind", "script.error") for r in records)),
              "marker_payloads": summaries, "origin_connections": origin.records,
              "block_request_validated": False, "block_session_validated": False,
              "request_rejection_observed": action != "observe" and bool(matches)
                   and any(r.get("kind") == "gate.denied" for r in records)
                   and not any(c.get("marker_in_origin_payload") for c in origin.records),
              "fixture_cleanup_terminated_child": not completed,
              "wss_streaming_coverage": "not_claimed", "frida_production_component": False}
    (root / "summary.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--codex", type=Path, default=shutil.which("codex"))
    parser.add_argument("--rva", type=lambda v: int(v, 0), default=0x3D703F0)
    parser.add_argument("--output", type=Path, default=Path("runs/guard-probe") / uuid4().hex)
    parser.add_argument("--action", choices=["observe", "block_request", "block_session", "terminate_process"], default="observe")
    args = parser.parse_args()
    if not args.codex or hashlib.sha256(args.codex.read_bytes()).hexdigest() != EXPECTED_HASH:
        parser.error("Official binary does not match the fixed research baseline")
    root = args.output.resolve(); root.mkdir(parents=True, exist_ok=False)
    results = [experiment(args.codex, root / t, t, args.rva, args.action) for t in ("http", "wss")]
    summary = {"binary_sha256": EXPECTED_HASH, "experiments": results}
    (root / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps({"output": str(root), **summary}, indent=2))


if __name__ == "__main__":
    main()
