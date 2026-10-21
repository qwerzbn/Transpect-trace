"""Fixed official Codex + TTQ1 request capture + local TLS hash oracle.

Fake data only. Does not certify default TLS trust, TUI, denial or a TLS backend.
The collector is disabled while the client remains alive so terminal health is
observed independently from process-exit inference. No request body is exported.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import threading
import time

from _build_support import ROOT, enter_repository
from probe_codex_tls import Origin, certificate, events
from transpect_trace.guard import BINARY_SHA256
from transpect_trace.guard.policy import GuardPolicy
from transpect_trace.observe.adapters import create_collector
from transpect_trace.observe.pipeline import Pipeline
from transpect_trace.observe.windows import discover_profile


def experiment(binary, dll, root, protocol, prompt_bytes, *, tls_probe=None, trusted_cert=None, trusted_key=None):
    if hashlib.sha256(binary.read_bytes()).hexdigest() != BINARY_SHA256:
        raise ValueError("fixed official Codex baseline mismatch")
    root.mkdir(parents=True, exist_ok=False)
    home, workspace = root / "codex-home", root / "workspace"
    home.mkdir(); workspace.mkdir()
    received, release = threading.Event(), threading.Event()
    expected = []
    def reply(payload):
        expected.append(dict(bytes=len(payload), sha256=hashlib.sha256(payload).hexdigest()))
        # WSS may prewarm before consuming the supplied prompt. Keep capture
        # active until the actual large request; do not certify just prewarm.
        if len(payload) < prompt_bytes:
            return events()
        received.set()
        if not release.wait(30):
            raise TimeoutError("collector terminal validation deadline")
        return events()
    if trusted_cert is not None:
        if trusted_key is None:raise ValueError('trusted origin certificate requires matching key')
        cert,key,ca=Path(trusted_cert),Path(trusted_key),None
    else:
        cert, key, ca = certificate(root)
    origin = Origin(root, cert, key, b"FAKE_REQUEST_CAPTURE", reply,allow_tls12=trusted_cert is not None)
    origin.thread.start()
    (home / "config.toml").write_text(
        'model_provider="capture_probe"\napproval_policy="never"\nsandbox_mode="read-only"\n'
        '[features]\nplugins=false\napps=false\n[model_providers.capture_probe]\n'
        f'name="Request capture fixture"\nbase_url="https://localhost:{origin.port}"\n'
        'wire_api="responses"\nrequires_openai_auth=false\nrequest_max_retries=0\nstream_max_retries=0\n'
        f'supports_websockets={str(protocol == "wss").lower()}\n[windows]\nsandbox="unelevated"\n', encoding="utf-8")
    env = {k:v for k,v in os.environ.items() if k.upper() not in {
        "CODEX_HOME", "CODEX_CA_CERTIFICATE", "SSL_CERT_FILE", "SSL_CERT_DIR", "SSLKEYLOGFILE", "RUST_LOG",
        "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "NODE_EXTRA_CA_CERTS",
        "OPENAI_API_KEY", "API_KEY", "ANTHROPIC_API_KEY", "OPENAI_BASE_URL", "CODEX_API_KEY", "CHATGPT_BASE_URL"
    } and "PROXY" not in k.upper()}
    env.update(CODEX_HOME=str(home), NO_PROXY="*", RUST_LOG="warn")
    if ca is not None:env['CODEX_CA_CERTIFICATE']=str(ca)
    command = [str(binary), "exec", "--json", "--ephemeral", "--skip-git-repo-check", "--model", "gpt-probe", "--cd", str(workspace), "-"]
    pipeline = Pipeline(root / "capture", GuardPolicy(credential_rules=False))
    collector = None
    with (root / "client.stdout.jsonl").open("wb") as out, (root / "client.stderr.log").open("wb") as err:
        child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=out, stderr=err, env=env, cwd=workspace)
        try:
            subject, profile = discover_profile(child.pid, "codex-cli")
            collector = create_collector("codex-request", subject, profile, pipeline=pipeline, dll=dll)
            collector.start()
            if tls_probe:tls_probe.start(subject)
            # A bounded UTF-8 prompt larger than legacy TTO1's 64 KiB frame.
            prompt = "FAKE_REQUEST_CAPTURE 中文\n" + "中" * ((prompt_bytes + 2)//3)
            child.stdin.write(prompt.encode("utf-8")); child.stdin.close()
            if not received.wait(30):
                raise RuntimeError("controlled source did not receive a complete request")
            deadline = time.monotonic() + 15
            while (not any(row['content_bytes']>=prompt_bytes for row in pipeline.rows)
                   and time.monotonic() < deadline):
                time.sleep(.01)
            collector.check_health()
            if tls_probe:tls_probe.close(subject)
            collector.close()
            release.set()
            code = child.wait(timeout=20)
        finally:
            release.set()
            if tls_probe:tls_probe.close()
            if child.poll() is None:
                child.terminate(); child.wait(timeout=10)
            if collector: collector.close()
            pipeline.finish()
            origin.stop.set(); origin.thread.join(timeout=15); origin.listener.close()
    captured = [dict(bytes=r["content_bytes"], sha256=r["content_sha256"]) for r in pipeline.rows]
    health = collector.status()
    # This constructor can execute more than once for a single actual send.
    # Hash agreement proves captured contents, never a unique send mapping.
    match = bool(expected) and all(row in captured for row in expected) and all(row in expected for row in captured)
    result = dict(protocol=protocol, adapter="codex-request", capture_layer="request-body",
        source="native-observer", prompt_target_bytes=prompt_bytes,
        source_request_hashes=expected, captured_request_hashes=captured,
        observations_are_unique_sends=False,
        source_hashes_match=match, actual_body_exceeds_one_mib=any(r["bytes"] > 1024*1024 for r in expected),
        capture_health=health, gaps=pipeline.gaps, client_exit_code=code,
        official_disk_unchanged=hashlib.sha256(binary.read_bytes()).hexdigest() == BINARY_SHA256,
        passed=match and not pipeline.gaps and health["terminal_health"] and code == 0,
        tls_plaintext_capture=False, tls_configuration="custom_ca_test_path" if ca is not None else "default-trust", can_enforce=False)
    result['source_tls_handshakes']=[{k:r[k] for k in ('connection','tls_version','cipher','protocol') if k in r}
        for r in origin.records if r.get('tls_version')]
    result['custom_trust_environment_names']=[name for name in ('CODEX_CA_CERTIFICATE','SSL_CERT_FILE','SSL_CERT_DIR','REQUESTS_CA_BUNDLE','CURL_CA_BUNDLE','NODE_EXTRA_CA_CERTS') if name in env]
    (root / "summary.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--codex", type=Path, required=True)
    parser.add_argument("--dll", type=Path, default=ROOT / "build/observe/ttrace-observe.dll")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--protocol", choices=["http", "wss", "both"], default="both")
    parser.add_argument("--prompt-bytes", type=int, default=1024*1024)
    args = parser.parse_args(); enter_repository()
    if not 1024 <= args.prompt_bytes <= 8*1024*1024:
        parser.error("fake prompt target must be between 1 KiB and 8 MiB")
    rows = [experiment(args.codex.resolve(), args.dll.resolve(), args.output.resolve()/p, p, args.prompt_bytes)
            for p in (["http", "wss"] if args.protocol == "both" else [args.protocol])]
    print(json.dumps(dict(passed=all(r["passed"] for r in rows), cases=rows), indent=2))
    if not all(r["passed"] for r in rows): raise SystemExit(1)


if __name__ == "__main__": main()
