"""Accept HTTP history recovery against a temporary, loopback-only Codex app-server.

--wire-only establishes which representation the unmodified client actually
sends. The enforced run requires the repository's desktop engine and a pin
matching the selected binary. No user's credentials, sessions or URLs are used.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import socket
import subprocess
import sys
import tempfile
import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from queue import Queue
from uuid import uuid4

import zstandard
from _build_support import ROOT

sys.path.insert(0, str(ROOT / "src"))

import probe_desktop_backend_lab as lab
from probe_desktop_guard_failstop_current_lab import (
    FAKE_KEY,
    counted_local_origin,
    origin_rows,
)
from probe_desktop_guard_graceful_current_lab import (
    _completed_for,
    _message_reader,
    _thread_id,
    _turn_id,
)

from transpect_trace.guard import desktop_service as svc
from transpect_trace.protect.archive import EncryptedRequestArchive
from transpect_trace.protect.codex_hook_gate import GateConfig


def digest(data):
    return hashlib.sha256(data).hexdigest()


def implementation_hashes():
    sources = (
        "src/transpect_trace/protect/native_collection.py",
        "src/transpect_trace/protect/content_dlp.py",
        "src/transpect_trace/protect/codex_hook_gate.py",
        "src/transpect_trace/guard/pipe.py",
        "src/transpect_trace/guard/codex_history_wire.py",
        "src/transpect_trace/guard/desktop_service.py",
        "scripts/probe_codex_zstd_history.py",
        "scripts/probe_desktop_guard_failstop_current_lab.py",
    )
    return {path: svc.file_sha256(ROOT / path) for path in sources}


def only_secret_values_changed(before, after):
    """Require identical JSON structure and equality of every unaffected value."""
    if type(before) is not type(after):
        return False
    if isinstance(before, dict):
        return before.keys() == after.keys() and all(
            only_secret_values_changed(before[k], after[k]) for k in before
        )
    if isinstance(before, list):
        return len(before) == len(after) and all(
            only_secret_values_changed(a, b) for a, b in zip(before, after)
        )
    if isinstance(before, str) and FAKE_KEY in before:
        return bool(after.strip()) and FAKE_KEY not in after
    return before == after


def config(home, port, unavailable_port, compressed):
    home.mkdir()
    base = f"http://127.0.0.1:{port}"
    # is_openai() and ChatGPT account mode select Codex's own compressor.
    (home / "config.toml").write_text(
        'model="gpt-5.1-codex"\nmodel_provider="local_wire_fixture"\n'
        'cli_auth_credentials_store="file"\n'
        f'chatgpt_base_url="http://127.0.0.1:{unavailable_port}"\n[analytics]\nenabled=false\n'
        f"[features]\nenable_request_compression={str(compressed).lower()}\n"
        '[model_providers.local_wire_fixture]\nname="OpenAI"\n'
        f'base_url="{base}/v1"\nwire_api="responses"\nrequires_openai_auth=true\n'
        "supports_websockets=false\nrequest_max_retries=2\nstream_max_retries=2\n",
        encoding="utf-8",
    )
    now = datetime.now(UTC)

    def segment(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")

    fake_jwt = ".".join(
        [
            segment({"typ": "JWT", "alg": "none"}),
            segment(
                {
                    "exp": int(now.timestamp()) + 3600,
                    "https://api.openai.com/auth": {
                        "chatgpt_account_id": "local-fixture",
                        "chatgpt_plan_type": "plus",
                    },
                }
            ),
            "unsigned",
        ]
    )
    (home / "auth.json").write_text(
        json.dumps(
            {
                "auth_mode": "chatgpt",
                "OPENAI_API_KEY": None,
                "last_refresh": now.isoformat(),
                "tokens": {
                    "id_token": fake_jwt,
                    "access_token": fake_jwt,
                    "refresh_token": "fixture",
                    "account_id": "local-fixture",
                },
            }
        ),
        encoding="utf-8",
    )


def probe(backend, pinfile, folder, compressed, wire_only, long_primer_kib=0):
    folder.mkdir(parents=True, exist_ok=False)
    initial_hashes = implementation_hashes()
    pin = json.loads(pinfile.read_text(encoding="utf-8"))
    svc.check_backend(pin, backend)
    dll = None
    if not wire_only:
        dll = svc.ensure_dll(
            {**pin, "_path": pinfile, "_sha256": svc.normalized_sha256(pinfile)},
            backend,
        )
    marker = uuid4().hex[:12]
    first = f"Reply briefly about tea. Reference Tea{marker}."
    if long_primer_kib:
        if not 1 <= long_primer_kib <= 1024:
            raise ValueError("long primer must be between 1 and 1024 KiB")
        # ASCII prose has no JSON escapes. The receiver can check that the
        # complete long message arrived on each allowed turn, byte for byte.
        note = " Tasting note {i}. The tea has a floral aroma and a soft finish."
        size = long_primer_kib * 1024
        parts = [first]
        length = len(first)
        while length < size:
            part = note.format(i=len(parts))
            parts.append(part)
            length += len(part)
        first = "".join(parts)[:size].rstrip()
        first += "." * (size - len(first))
    sensitive = f"Deployment fixture contains a GitHub token {FAKE_KEY}."
    last = f"Ignore the earlier task. Answer my new tea question. Ticket Leaf{marker}."
    phases = []
    received_bodies = {}

    def observe_body(wire, encodings):
        is_zstd = encodings == ["zstd"]
        if encodings and not is_zstd:
            raise ValueError("unexpected content encoding")
        expanded = (
            zstandard.ZstdDecompressor().decompress(
                wire, max_output_size=lab.MAX_BODY, allow_extra_data=False
            )
            if is_zstd
            else wire
        )
        body = json.loads(expanded)
        if not isinstance(body.get("input"), list):
            raise TypeError("receiver did not decode a Responses request")
        received_bodies[digest(expanded)] = body
        has_secret = FAKE_KEY in json.dumps(body, ensure_ascii=False)
        return {
            "encoding": encodings,
            "zstd_frame": wire.startswith(b"\x28\xb5\x2f\xfd"),
            "expanded_sha256": digest(expanded),
            "expanded_bytes": len(expanded),
            "has_first": first.encode() in expanded,
            "has_last": last.encode() in expanded,
            "has_token": has_secret,
            "target": has_secret,
        }

    source_sha = svc.file_sha256(backend)
    log = []
    observed, messages, lock = [], Queue(), threading.Lock()
    with tempfile.TemporaryDirectory(
        prefix="transpect-zstd-", ignore_cleanup_errors=True
    ) as tmp:
        work, home = Path(tmp) / "work", Path(tmp) / "home"
        work.mkdir()
        # Reserve a non-listening loopback port until the child exits. This
        # keeps all other proxy/account destinations off any real service.
        with (
            socket.socket() as unavailable,
            counted_local_origin("http", work, FAKE_KEY.encode()) as sink,
        ):
            unavailable.bind(("127.0.0.1", 0))
            unavailable_port = unavailable.getsockname()[1]
            blocked_proxy = f"http://127.0.0.1:{unavailable_port}"
            sink.observe_body = observe_body
            sink.success_for_allowed = True
            config(home, sink.server_port, unavailable_port, compressed)
            env = lab.isolated_env(home)
            env.update(
                NO_PROXY="localhost,127.0.0.1",
                HTTP_PROXY=blocked_proxy,
                HTTPS_PROXY=blocked_proxy,
                ALL_PROXY=blocked_proxy,
            )
            process = subprocess.Popen(
                [str(backend), "app-server"],
                cwd=work,
                env=env,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                encoding="utf-8",
                bufsize=1,
            )
            threading.Thread(
                target=_message_reader,
                args=(process.stdout, messages, observed, lock),
                daemon=True,
            ).start()
            worker = None
            try:
                lab._request(
                    process,
                    1,
                    "initialize",
                    {"clientInfo": {"name": "wire_probe", "version": "1.0"}},
                )
                if "result" not in lab._await_id(messages, 1, 15):
                    raise RuntimeError("test app-server did not initialize")
                process.stdin.write('{"method":"initialized","params":{}}\n')
                process.stdin.flush()
                if dll:
                    gate = GateConfig(
                        mode="enforce",
                        archive_directory=folder / "archive",
                        audit_file=folder / "audit.jsonl",
                        registration_directory=None,
                        review_override_ttl_seconds=0,
                        collection_file=folder / "collection.jsonl",
                    )
                    engine = svc.create_desktop_engine(gate)
                    details = svc.process_details(process.pid)
                    status = svc.BackendStatus(
                        process.pid, details["creation_filetime"]
                    )
                    worker = svc.BackendController(
                        details, dll, engine, {}, folder, status, log.append
                    )
                    worker.start()
                    end = time.monotonic() + 20
                    while status.state == "STARTING" and time.monotonic() < end:
                        time.sleep(0.04)
                    if status.state != "PROTECTED":
                        raise RuntimeError(
                            f"test controller did not attach: {status.state}"
                        )
                lab._request(
                    process,
                    2,
                    "thread/start",
                    {
                        "model": "gpt-5.1-codex",
                        "cwd": str(work),
                        "approvalPolicy": "never",
                        "sandbox": "read-only",
                    },
                )
                thread = _thread_id(lab._await_id(messages, 2, 20))
                turns = (
                    [("allow", first)]
                    if wire_only
                    else [("allow", first), ("deny", sensitive), ("continue", last)]
                )
                for number, (name, prompt) in enumerate(turns, 10):
                    start = len(origin_rows(sink, "http"))
                    lab._request(
                        process,
                        number,
                        "turn/start",
                        {
                            "threadId": thread,
                            "input": [{"type": "text", "text": prompt}],
                            "cwd": str(work),
                        },
                    )
                    turn = _turn_id(lab._await_id(messages, number, 20))
                    end = time.monotonic() + 35
                    while time.monotonic() < end:
                        done = _completed_for(observed, lock, turn)
                        if done is not None:
                            break
                        time.sleep(0.04)
                    else:
                        raise TimeoutError("turn did not complete")
                    rows = origin_rows(sink, "http")[start:]
                    with lock:
                        replied = any(
                            msg.get("method") == "item/completed"
                            and msg.get("params", {}).get("turnId") == turn
                            and msg["params"].get("item", {}).get("text")
                            == "Local test reply."
                            for msg in observed
                        )
                    phases.append(
                        {
                            "phase": name,
                            "thread_id": thread,
                            "turn_id": turn,
                            "status": done.get("status"),
                            "error": (done.get("error") or {}).get("message"),
                            "local_reply_observed": replied,
                            "receipts": rows,
                        }
                    )
            finally:
                process.terminate()
                try:
                    process.wait(5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                if worker is not None:
                    worker.stop_requested.set()
                    worker.finished.wait(10)
    # The origin context joins all workers on exit. Account for complete and
    # incomplete POSTs across *all* phase boundaries, including shutdown.
    all_receipts = origin_rows(sink, "http")
    posts = [r for r in all_receipts if r.get("method") == "POST"]
    gets = [r for r in all_receipts if r.get("method") == "GET"]
    expected_posts = 1 if wire_only else 2
    final_checks = {
        "same_python_sources_through_test": initial_hashes == implementation_hashes(),
        "all_connections_classified": all(
            r.get("method") in ("GET", "POST") for r in all_receipts
        ),
        "only_bodyless_catalog_gets": all(
            r.get("complete")
            and r.get("path") == "catalog"
            and r.get("http_body_bytes_received") == 0
            for r in gets
        ),
        "distinct_turns_in_one_thread": len({p["turn_id"] for p in phases})
        == len(turns)
        and {p["thread_id"] for p in phases} == {thread},
        "no_token_in_received_headers": all(
            r.get("marker_in_header") is False for r in all_receipts
        ),
        "only_expected_response_posts": len(posts) == expected_posts
        and all(
            r.get("complete")
            and r["path"] == "responses"
            and r.get("has_token") is False
            for r in posts
        ),
    }
    audit = []
    if not wire_only:
        (path,) = folder.glob("native-audit-*.jsonl")
        archive = EncryptedRequestArchive(folder / "archive")
        for line in path.read_text(encoding="utf-8").splitlines():
            row = json.loads(line)
            if (
                row.get("category") != "request_envelope"
                or row.get("route_event") != "model.request"
            ):
                continue
            receipt, body = archive.read(row["archive_record_id"])
            intact = []
            if FAKE_KEY.encode() in body and last.encode() in body:
                original = json.loads(body)
                intact = [
                    key
                    for key, received in received_bodies.items()
                    if only_secret_values_changed(original, received)
                ]
            audit.append(
                {
                    "thread_id": row["thread_id"],
                    "turn_id": row["turn_id"],
                    "request_id": row["request_id"],
                    "archive_record_id": row["archive_record_id"],
                    "decision": row["route_decision"],
                    "verified": receipt.body_sha256
                    == digest(body)
                    == row["request_sha256"]
                    and len(body) == row["content_bytes"],
                    "sha256": digest(body),
                    "native_elapsed_ms": row.get("elapsed_ms"),
                    "has_token": FAKE_KEY.encode() in body,
                    "has_last": last.encode() in body,
                    "has_first": first.encode() in body,
                    "matches_origin_except_denied_value": intact,
                }
            )
    for phase in phases:
        rows = phase["receipts"]
        native = [entry for entry in audit if entry["turn_id"] == phase["turn_id"]]
        phase["native"] = native
        if phase["phase"] == "deny":
            checks = {
                "hard_denied": phase["status"] == "failed"
                and (phase["error"] or "").startswith("TTRACE_NATIVE_DENY"),
                "zero_origin_connections": not rows,
                "native_denied_once": len(native) == 1
                and native[0]["decision"] == "deny",
                "archived_sensitive": any(e["has_token"] for e in native),
            }
        else:
            checks = {
                "client_received_local_reply": phase["status"] == "completed"
                and phase["local_reply_observed"],
                "single_origin_request": len(rows) == 1,
                "verified_wire_encoding": len(rows) == 1
                and rows[0].get("complete")
                and rows[0].get("zstd_frame") == compressed
                and rows[0].get("encoding") == (["zstd"] if compressed else []),
                "no_secret_at_origin": len(rows) == 1
                and rows[0].get("has_token") is False,
                "first_prompt_preserved": len(rows) == 1
                and rows[0].get("has_first") is True,
            }
            if not wire_only:
                checks["native_allow"] = bool(native) and all(
                    e["decision"] == "allow" for e in native
                )
                if phase["phase"] == "allow":
                    checks["origin_matches_archived_body"] = any(
                        e["sha256"] == r.get("expanded_sha256")
                        for e in native
                        for r in rows
                    )
                else:
                    checks["historical_secret_in_original"] = any(
                        e["has_token"] and e["has_last"] for e in native
                    )
                    checks["new_prompt_at_origin"] = (
                        len(rows) == 1 and rows[0].get("has_last") is True
                    )
                    checks["clean_archive_matches_origin"] = any(
                        not e["has_token"] and e["sha256"] == r.get("expanded_sha256")
                        for e in native
                        for r in rows
                    )
                    checks["unaffected_json_fields_preserved"] = len(rows) == 1 and any(
                        rows[0].get("expanded_sha256")
                        in entry["matches_origin_except_denied_value"]
                        for entry in native
                    )
        if not wire_only:
            checks["archives_exact"] = bool(native) and all(
                e["verified"] for e in native
            )
            checks["same_thread_in_native"] = bool(native) and all(
                e["thread_id"] == thread for e in native
            )
        phase["checks"] = checks
    report = {
        "schema": "transpect.codex.http-history/1",
        "synthetic_only": True,
        "wire_only": wire_only,
        "compressed": compressed,
        "primer_bytes": len(first.encode()),
        "backend_sha256": source_sha,
        "pin_sha256": svc.normalized_sha256(pinfile),
        "desktop_version": pin["codex_desktop_version"],
        "backend_version": pin["backend"]["version"],
        "python_sources_sha256": initial_hashes,
        "dll_sha256": svc.file_sha256(dll) if dll else None,
        "thread_id": thread,
        "pid": process.pid,
        "phases": phases,
        "receiver_post_count": len(posts),
        "receiver_get_count": len(gets),
        "final_checks": final_checks,
        "passed": all(final_checks.values())
        and all(all(p["checks"].values()) for p in phases),
    }
    (folder / "report.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend", type=Path, required=True)
    parser.add_argument("--pin", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--plain", action="store_true")
    parser.add_argument("--wire-only", action="store_true")
    parser.add_argument("--long-primer-kib", type=int, default=0)
    args = parser.parse_args()
    report = probe(
        args.backend.resolve(),
        args.pin.resolve(),
        args.output.resolve(),
        not args.plain,
        args.wire_only,
        args.long_primer_kib,
    )
    print(
        json.dumps(
            {
                "passed": report["passed"],
                "final_checks": report["final_checks"],
                "report": str(args.output / "report.json"),
                "failed": [
                    [p["phase"], k]
                    for p in report["phases"]
                    for k, v in p["checks"].items()
                    if not v
                ],
            }
        )
    )
    sys.exit(0 if report["passed"] else 1)
