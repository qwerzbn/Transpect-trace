"""Claude Code 固定版多轮门控探针：脚本化 SSE 对端 + stream-json 驱动。

本探针不调用真实模型。本地 HTTPS 源站按 POST 序号脚本化响应：
  text      -> 返回一条 "OK" 文本回复（正常结束回合）
  tool_use  -> 返回一个 tool_use（Read / Bash），客户端本地执行后发第二请求
其余 -> 403（与基线探针一致，并保留逐字节记录）。

用于验收：
  ABI 会话存活：m1 放行 -> m2 拒绝（源站 0 字节）-> m3 放行，同一进程完成；
  场景 4：Read 工具结果携带合成令牌的后续请求被拒绝；
  场景 5：Bash base64 工具结果被解码识别并拒绝。
"""
from __future__ import annotations

import argparse
from contextlib import nullcontext
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

import probe_claude_inprocess_lab as base  # noqa: E402
from _build_support import ROOT  # noqa: E402

sys.path.insert(0, str(ROOT / "src"))
from transpect_trace.guard import claude_service as lab  # noqa: E402
from transpect_trace.guard import desktop_service as common  # noqa: E402
from transpect_trace.guard.desktop_service import (  # noqa: E402
    Lease, current_user_sid, process_details, resident_guard_dlls)
from transpect_trace.guard.native import inject, wait_ready  # noqa: E402
from transpect_trace.guard.pipe import PipeServer  # noqa: E402

FAKE_KEY = "ghp_" + "a1B2c3D4e5F6g7H8iJ9J0k1L2m3N4o5P6q7R8"
SECRET_LINE = "内部令牌：" + FAKE_KEY + " 请勿外传。\n"


def _sse(event: str, payload: dict) -> bytes:
    return f"event: {event}\ndata: {json.dumps(payload, ensure_ascii=False)}\n\n".encode()


def _text_reply(text: str) -> bytes:
    out = b""
    out += _sse("message_start", {"type": "message_start", "message": {
        "id": "msg_01", "type": "message", "role": "assistant",
        "model": "claude-haiku-5-5", "content": [], "stop_reason": None,
        "stop_sequence": None, "usage": {"input_tokens": 1, "output_tokens": 1}}})
    out += _sse("content_block_start", {"type": "content_block_start", "index": 0,
                                        "content_block": {"type": "text", "text": ""}})
    out += _sse("content_block_delta", {"type": "content_block_delta", "index": 0,
                                        "delta": {"type": "text_delta", "text": text}})
    out += _sse("content_block_stop", {"type": "content_block_stop", "index": 0})
    out += _sse("message_delta", {"type": "message_delta",
                                  "delta": {"stop_reason": "end_turn", "stop_sequence": None},
                                  "usage": {"output_tokens": 1}})
    out += _sse("message_stop", {"type": "message_stop"})
    return out


def _tool_use_reply(name: str, arguments: dict) -> bytes:
    out = b""
    out += _sse("message_start", {"type": "message_start", "message": {
        "id": "msg_01", "type": "message", "role": "assistant",
        "model": "claude-haiku-5-5", "content": [], "stop_reason": None,
        "stop_sequence": None, "usage": {"input_tokens": 1, "output_tokens": 1}}})
    out += _sse("content_block_start", {"type": "content_block_start", "index": 0,
                                        "content_block": {"type": "tool_use",
                                                          "id": "toolu_01X", "name": name,
                                                          "input": {}}})
    out += _sse("content_block_delta", {
        "type": "content_block_delta", "index": 0,
        "delta": {"type": "input_json_delta",
                  "partial_json": json.dumps(arguments, ensure_ascii=False)}})
    out += _sse("content_block_stop", {"type": "content_block_stop", "index": 0})
    out += _sse("message_delta", {"type": "message_delta",
                                  "delta": {"stop_reason": "tool_use", "stop_sequence": None},
                                  "usage": {"output_tokens": 1}})
    out += _sse("message_stop", {"type": "message_stop"})
    return out


class ScriptedOrigin(base.LocalTlsOrigin):
    """LocalTlsOrigin with scripted responses per /v1/messages POST ordinal."""

    def __init__(self, directory: Path, openssl: str, auth: str, marker: str,
                 plans: list[dict], secondary_markers: tuple[str, ...] = ()):
        self.plans = plans
        self.post_count = 0
        self.secondary_markers = tuple(value.encode("utf-8") for value in secondary_markers)
        super().__init__(directory, openssl, auth, marker)

    def _handle(self, connection: socket.socket) -> None:
        data = bytearray()
        complete = False
        body = b""
        auth_matches = False
        fields = {}
        try:
            with self.context.wrap_socket(connection, server_side=True) as secure:
                secure.settimeout(3)
                while len(data) <= base.MAX_WIRE_BYTES:
                    try:
                        part = secure.recv(65536)
                    except (socket.timeout, OSError):
                        break
                    if not part:
                        break
                    data.extend(part)
                    end = data.find(b"\r\n\r\n")
                    if end < 0:
                        continue
                    header = bytes(data[:end]).split(b"\r\n")
                    first_line = header[0]
                    if first_line.startswith(b"HEAD "):
                        complete = True
                        secure.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                        break
                    if first_line.startswith(b"GET /inference-profiles"):
                        complete = True
                        response = b'{"inferenceProfileSummaries":[]}'
                        secure.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                                       + f"Content-Length: {len(response)}\r\nConnection: close\r\n\r\n".encode()
                                       + response)
                        break
                    if not first_line.startswith(b"POST "):
                        break
                    fields = {}
                    for line in header[1:]:
                        name, sep, value = line.partition(b":")
                        if sep:
                            fields[name.lower()] = value.strip()
                    try:
                        length = int(fields[b"content-length"])
                    except (KeyError, ValueError):
                        break
                    if length < 0 or length > base.MAX_WIRE_BYTES:
                        break
                    if len(data) < end + 4 + length:
                        continue
                    body = bytes(data[end + 4:end + 4 + length])
                    expected = (b"Bearer synthetic-lab-token" if self.auth == "bearer"
                                else b"synthetic-lab-api-key")
                    credential = (fields.get(b"authorization") if self.auth == "bearer"
                                  else fields.get(b"x-api-key"))
                    auth_matches = credential == expected
                    complete = True
                    is_messages = b"/v1/messages" in first_line
                    if is_messages and self.post_count < len(self.plans):
                        plan = self.plans[self.post_count]
                        self.post_count += 1
                        if plan.get("kind") == "text":
                            payload = _text_reply(plan.get("text", "OK"))
                        elif plan.get("kind") == "tool_use":
                            payload = _tool_use_reply(plan["tool"], plan.get("input", {}))
                        else:
                            payload = (b'{"type":"error","error":{"type":"permission_error",'
                                       b'"message":"isolated lab upstream"}}')
                            secure.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\n"
                                           + f"Content-Length: {len(payload)}\r\nConnection: close\r\n\r\n".encode()
                                           + payload)
                            break
                        secure.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n"
                                       + f"Content-Length: {len(payload)}\r\nConnection: close\r\n\r\n".encode()
                                       + payload)
                    else:
                        payload = (b'{"type":"error","error":{"type":"permission_error",'
                                   b'"message":"isolated lab upstream"}}')
                        secure.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\n"
                                       + f"Content-Length: {len(payload)}\r\nConnection: close\r\n\r\n".encode()
                                       + payload)
                    break
        except (OSError, ssl.SSLError):
            pass
        finally:
            raw = bytes(data)
            first = raw.split(b"\r\n", 1)[0]
            encoding = fields.get(b"content-encoding", b"").lower()
            try:
                decoded = gzip.decompress(body) if encoding == b"gzip" else body
            except (OSError, EOFError):
                decoded = b""
            record = {"app_bytes": len(raw), "starts_post": first.startswith(b"POST "),
                      "request_line": first[:256].decode("ascii", "replace"),
                      "complete": complete, "body_bytes": len(body),
                      "body_sha256": hashlib.sha256(body).hexdigest() if body else None,
                      "marker_offset": body.find(self.marker) if body else -1,
                      "decoded_body_bytes": len(decoded),
                      "decoded_body_sha256": hashlib.sha256(decoded).hexdigest() if decoded else None,
                      "decoded_marker_offset": decoded.find(self.marker) if decoded else -1,
                      "secondary_marker_offsets": [body.find(value) if body else -1
                                                   for value in self.secondary_markers],
                      "decoded_secondary_marker_offsets": [decoded.find(value) if decoded else -1
                                                           for value in self.secondary_markers],
                      "content_encoding": encoding.decode("ascii", "replace"),
                      "auth_matches": auth_matches}
            with self.lock:
                self.records.append(record)
            connection.close()


def run_session(test: dict, binary: Path, openssl: str, deny_mode: str,
                evidence_dir: Path | None = None) -> dict:
    """Drive one multi-turn session; return observed evidence."""
    messages = test["messages"]       # list of (text, expected_sink_kind)
    plans = test["plans"]             # scripted responses per allowed POST
    tools = test.get("tools", "")     # --tools value ("" = none)
    max_turns = test.get("max_turns", 1)
    secret_file = test.get("secret_file")  # optional file content for scenario 4/5
    marker = test["marker"]

    if evidence_dir is not None:
        evidence_dir = evidence_dir.resolve()
        evidence_dir.mkdir(parents=True, exist_ok=False)
    context = (nullcontext(str(evidence_dir)) if evidence_dir is not None
               else tempfile.TemporaryDirectory(prefix="ttrace-cc-multi-"))
    with context as temp:
        directory = Path(temp)
        system = directory / "system.txt"
        system.write_text("You are concise.", encoding="utf-8")
        if secret_file is not None:
            (directory / "secret.txt").write_text(secret_file, encoding="utf-8")
        origin = ScriptedOrigin(directory, openssl, "bearer", marker, plans)
        child = None
        pipe = None
        lease = None
        try:
            env = base.isolated_env(directory, origin, "bearer")
            env["TTRACE_DENY_MODE"] = deny_mode
            # 拒绝语义依赖零重试预算：软拒绝在首次尝试即结束回合（DLL 内
            # 也尝试锁定该值，但客户端可能在注入完成前已读取默认值）。
            env["CLAUDE_CODE_MAX_RETRIES"] = "0"
            if test.get("gzip_body"):
                env["CLAUDE_CODE_GZIP_REQUEST_BODIES"] = "1"
            if test.get("realistic_traffic"):
                # 复现真实终端形态：允许特性开关等非模型启动流量（旧版对
                # 这些请求 fail-stop 杀进程；修复后应原样放行）
                env.pop("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", None)
            if test.get("anthropic_prefix"):
                # 复现真实 TUI 形态：中转基址带 /anthropic 路径前缀，
                # 模型请求行为 POST /anthropic/v1/messages（诊断实测确认）。
                # 进程环境与 settings.json env 块都要改（后者优先级更高）。
                suffixed = env["ANTHROPIC_BASE_URL"].rstrip("/") + "/anthropic"
                env["ANTHROPIC_BASE_URL"] = suffixed
                settings_path = directory / "settings.json"
                if settings_path.exists():
                    settings = json.loads(settings_path.read_text(encoding="utf-8"))
                    block = settings.get("env")
                    if isinstance(block, dict) and "ANTHROPIC_BASE_URL" in block:
                        block["ANTHROPIC_BASE_URL"] = suffixed
                        settings_path.write_text(json.dumps(settings, ensure_ascii=False),
                                                encoding="utf-8")
            child_args = ["--input-format", "stream-json", "--output-format", "stream-json",
                          "--verbose", "--system-prompt-file", str(system)]
            if tools:
                child_args += ["--tools", tools, "--permission-mode", "bypassPermissions"]
            else:
                child_args += ["--tools", ""]
            run_dir = Path(directory) / "state" / "runs" / (
                f"{time.strftime('%Y%m%d-%H%M%S')}-{os.getpid()}-{time.time_ns()}")
            run_dir.mkdir(parents=True)
            engine = lab._engine(run_dir)
            child_env = env
            child_env["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"] = "1"
            if not test.get("gzip_body"):
                child_env["CLAUDE_CODE_GZIP_REQUEST_BODIES"] = "0"
            child = subprocess.Popen(
                [str(binary), "-p", "--max-turns", str(max_turns),
                 "--no-session-persistence", *child_args],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env=child_env, cwd=directory)
            details = None
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and child.poll() is None:
                details = process_details(child.pid)
                if details is not None:
                    break
                time.sleep(0.05)
            if details is None or child.poll() is not None:
                raise RuntimeError("Claude exited before its identity was established")
            if details["user_sid"] != current_user_sid():
                raise RuntimeError("Claude is running under a different user")
            lab.check_binary(lab.load_pin(), Path(details["image_path"]))
            if resident_guard_dlls(child.pid):
                raise RuntimeError("Claude process already has a guard DLL")
            birth = details["creation_filetime"]
            identity = {"pid": child.pid, "creation_filetime": birth,
                        "guard_session_id": f"{child.pid}-{birth}",
                        "baseline": {"path": details["image_path"]}}
            pipe = PipeServer(child.pid, common._DecisionLog(engine, {}, lambda *_a: None),
                              run_dir / "native-audit.jsonl",
                              client_sid=details["user_sid"])
            pipe.start()
            lease = Lease(child.pid, birth)
            lease.acquire()
            inject(child.pid, lab.ensure_dll(lab.load_pin(), binary), identity,
                   identity_resolver=lambda _pid: dict(identity))
            if not wait_ready(identity, 15):
                audit_rows = []
                audit_path = run_dir / "native-audit.jsonl"
                if audit_path.exists():
                    audit_rows = audit_path.read_text(encoding="utf-8").splitlines()[-6:]
                raise RuntimeError(
                    "Claude native hook did not become ready; "
                    f"child_poll={child.poll()}; audit_tail={audit_rows}")

            out_lines: list[str] = []
            def reader():
                assert child.stdout is not None
                for line in child.stdout:
                    out_lines.append(line.decode("utf-8", "replace"))
            thread = threading.Thread(target=reader, daemon=True)
            thread.start()

            results = []
            assert child.stdin is not None
            seen = 0
            for text, _kind in messages:
                payload = json.dumps({"type": "user", "message": {
                    "role": "user", "content": [{"type": "text", "text": text}]}},
                    ensure_ascii=False) + "\n"
                child.stdin.write(payload.encode("utf-8"))
                child.stdin.flush()
                result = None
                wait_deadline = time.monotonic() + 60
                while time.monotonic() < wait_deadline and child.poll() is None:
                    for index in range(seen, len(out_lines)):
                        line = out_lines[index]
                        if '"type":"result"' in line:
                            seen = index + 1
                            try:
                                parsed = json.loads(line)
                                result = {"subtype": parsed.get("subtype"),
                                          "is_error": parsed.get("is_error"),
                                          "duration_ms": parsed.get("duration_ms")}
                            except Exception:
                                result = {"raw": line[:200]}
                            break
                    if result:
                        break
                    time.sleep(0.2)
                if result is None:
                    seen = len(out_lines)  # skip stale lines for the next turn
                results.append({"text": text[:60], "result": result})
                time.sleep(2)  # let the turn fully settle
            child.stdin.close()
            try:
                exit_code = child.wait(timeout=30)
            except subprocess.TimeoutExpired:
                child.kill()
                exit_code = "KILLED"
            stderr = b""
            assert child.stderr is not None
            stderr = child.stderr.read()
            origin.close()
            records = origin.snapshot()
            if evidence_dir is not None:
                (directory / "origin-receipt.json").write_text(json.dumps({
                    "schema": "transpect.claude.local-origin-receipt/1.0",
                    "mode": "no_forward", "marker_sha256": hashlib.sha256(marker.encode()).hexdigest(),
                    "records": records,
                }, ensure_ascii=False, indent=2), encoding="utf-8")
            decisions = []
            blocked_items = []
            collection_trace = []
            if (run_dir / "native-audit.jsonl").exists():
                for line in (run_dir / "native-audit.jsonl").read_text(
                        encoding="utf-8").splitlines():
                    row = json.loads(line)
                    if row.get("route_event") == "model.request":
                        decisions.append(row.get("decision"))
            if (run_dir / "collection.jsonl").exists():
                for line in (run_dir / "collection.jsonl").read_text(
                        encoding="utf-8").splitlines():
                    item = json.loads(line)
                    collection_trace.append({
                        "request_id": item.get("request_id"),
                        "category": item.get("category"),
                        "location": item.get("location"),
                        "action": item.get("actionable_decision"),
                        "archive_record_id": item.get("archive_record_id") if item.get("category") == "request_envelope" else None,
                        "request_sha256": item.get("request_sha256") if item.get("category") == "request_envelope" else None,
                        "extra": item.get("extra") if item.get("category") == "request_envelope" else None,
                    })
                    if item.get("actionable_decision") == "BLOCK":
                        blocked_items.append({
                            "category": item.get("category"),
                            "location": item.get("location"),
                            "rules": item.get("matched_rule_ids")})
            posts = [r for r in records if r["starts_post"]]
            pass_through = [r for r in records
                            if not (r["request_line"].startswith("POST /v1/messages")
                                    or r["request_line"].startswith("POST /anthropic/v1/messages"))]
            diagnostics_path = directory / "TranspectTrace" / "claude-guard" / "diagnostics.jsonl"
            diagnostics = []
            if diagnostics_path.exists():
                diagnostics = [json.loads(line) for line in diagnostics_path.read_text(
                    encoding="utf-8").splitlines() if line.strip()]
            return {"exit": exit_code,
                    "decisions": decisions,
                    "blocked_items": blocked_items,
                    "collection_trace": collection_trace[-24:],
                    "post_count": len(posts),
                    "pass_through_records": [{"request_line": r["request_line"][:120],
                                              "app_bytes": r["app_bytes"]}
                                             for r in pass_through],
                    "sink_bodies": [{"body_bytes": r["body_bytes"],
                                     "body_sha256": r["body_sha256"],
                                     "marker_offset": r["marker_offset"],
                                     "content_encoding": r["content_encoding"],
                                     "request_line": r["request_line"][:80]}
                                    for r in posts],
                    "turn_results": results,
                    "diagnostics": diagnostics[-20:],
                    "stderr_tail": stderr.decode("utf-8", "replace")[-300:]}
        finally:
            if child is not None:
                if child.poll() is None:
                    child.kill()
                child.wait(timeout=5)
                for stream in (child.stdin, child.stdout, child.stderr):
                    if stream is not None:
                        stream.close()
            if pipe is not None:
                pipe.close()
            if lease is not None and lease.handle is not None:
                lease.release(controlled=False)
            origin.close()


TESTS = {
    "anthropic_prefix_allow": {
        # TUI 真实路径形态：POST /anthropic/v1/messages 必须被门控放行
        "marker": "sunny day",
        "messages": [("Reply OK", "allowed")],
        "plans": [{"kind": "text", "text": "OK"}],
        "tools": "",
        "max_turns": 1,
        "anthropic_prefix": True,
    },
    "realistic_benign_allow": {
        # 非模型启动流量放行 + 良性模型请求正常门控放行。
        # -p 路径实测并不压缩，gzip 另由 Native 专项探针覆盖。
        "marker": "sunny day",
        "messages": [("Reply OK", "allowed")],
        "plans": [{"kind": "text", "text": "OK"}],
        "tools": "",
        "max_turns": 1,
        "realistic_traffic": True,
    },
    "gzip_benign_allow": {
        # 真实终端形态：客户端默认 gzip 压缩请求体；正常请求必须放行
        "marker": "sunny day",
        "messages": [("Reply OK", "allowed")],
        "plans": [{"kind": "text", "text": "OK"}],
        "tools": "",
        "max_turns": 1,
        "gzip_body": True,
    },
    "abi_session": {
        "marker": FAKE_KEY,
        "messages": [
            ("Reply OK", "allowed"),
            ("请原样回复：内部令牌是 " + FAKE_KEY, "denied"),
            ("Reply OK", "allowed"),
        ],
        "plans": [{"kind": "text", "text": "OK"}, {"kind": "text", "text": "OK"},
                  {"kind": "text", "text": "OK"}],
        "tools": "",
    },
    "scenario4_tool_result": {
        "marker": FAKE_KEY,
        "secret_file": SECRET_LINE,
        "messages": [("读取 secret.txt 并原样输出", "allowed")],
        "plans": [{"kind": "tool_use", "tool": "Read",
                   "input": {"file_path": "secret.txt"}},
                  {"kind": "text", "text": "OK"}],
        "tools": "Read",
        "max_turns": 2,
    },
    "scenario4_block_continue": {
        "marker": FAKE_KEY,
        "secret_file": SECRET_LINE,
        "messages": [("读取 secret.txt 并原样输出", "allowed"),
                     ("现在只回答 OK，不再读取文件", "allowed")],
        "plans": [{"kind": "tool_use", "tool": "Read",
                   "input": {"file_path": "secret.txt"}},
                  {"kind": "text", "text": "OK"}],
        "tools": "Read",
        "max_turns": 3,
    },
    "scenario4_gzip": {
        # 红action 模式 + gzip 请求体：清洗正文必须重压缩并重写 Content-Length，
        # 源站收到的请求必须合法可解析。
        "marker": FAKE_KEY,
        "secret_file": SECRET_LINE,
        "messages": [("读取 secret.txt 并原样输出", "allowed")],
        "plans": [{"kind": "tool_use", "tool": "Read",
                   "input": {"file_path": "secret.txt"}},
                  {"kind": "text", "text": "OK"}],
        "tools": "Read",
        "max_turns": 2,
        "gzip_body": True,
    },
    "scenario5_base64": {
        "marker": FAKE_KEY,
        "secret_file": SECRET_LINE,
        "messages": [("用命令 cat secret.txt | base64 输出编码结果", "allowed")],
        "plans": [{"kind": "tool_use", "tool": "Bash",
                   "input": {"command": "cat secret.txt | base64"}},
                  {"kind": "text", "text": "OK"}],
        "tools": "Bash",
        "max_turns": 2,
    },
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=None)
    parser.add_argument("--test", choices=list(TESTS), default=None)
    parser.add_argument("--deny-mode", default="kill", help="TTRACE_DENY_MODE value")
    parser.add_argument("--evidence-dir", type=Path,
                        help="retain Native audit, encrypted archive and local origin receipt")
    args = parser.parse_args()
    openssl = shutil.which("openssl")
    if not openssl:
        parser.error("openssl is required")
    binary = (args.binary or lab.installed_claude()).resolve(strict=True)
    lab.check_binary(lab.load_pin(), binary)
    selected = list(TESTS) if args.test is None else [args.test]
    failed = False
    for name in selected:
        try:
            case_dir = args.evidence_dir / name if args.evidence_dir else None
            evidence = run_session(TESTS[name], binary, openssl, args.deny_mode, case_dir)
            if name in ("scenario4_tool_result", "scenario4_gzip"):
                expected, expected_posts = ["allow", "deny"], 1
            elif name == "scenario4_block_continue":
                expected, expected_posts = ["allow", "deny", "allow"], 2
            elif name == "scenario5_base64":
                expected, expected_posts = ["allow", "deny"], 1
            elif name == "abi_session":
                expected, expected_posts = ["allow", "deny", "allow"], 2
            else:
                expected, expected_posts = ["allow"], 1
            if evidence["decisions"] != expected:
                raise AssertionError(f"decisions={evidence['decisions']}, expected={expected}")
            if evidence["post_count"] != expected_posts:
                raise AssertionError(f"post_count={evidence['post_count']}, expected={expected_posts}; "
                                     f"diagnostics={evidence['diagnostics'][-8:]}")
            if TESTS[name].get("gzip_body") and any(
                    row["content_encoding"] != "gzip" for row in evidence["sink_bodies"]):
                raise AssertionError("gzip test did not send gzip-compressed requests")
            if any(row["marker_offset"] >= 0 for row in evidence["sink_bodies"]
                   if name in ("abi_session", "scenario4_tool_result", "scenario4_block_continue",
                               "scenario4_gzip", "scenario5_base64")):
                raise AssertionError("sensitive marker reached the origin")
            if name == "abi_session":
                turns = evidence["turn_results"]
                if (len(turns) != 3 or not turns[0]["result"]
                        or turns[0]["result"].get("is_error")
                        or not turns[1]["result"]
                        or not turns[1]["result"].get("is_error")
                        or not turns[2]["result"]
                        or turns[2]["result"].get("is_error")):
                    raise AssertionError("blocked turn or later benign turn behaved incorrectly")
            elif name == "scenario4_block_continue":
                turns = evidence["turn_results"]
                if (len(turns) != 2 or not turns[0]["result"]
                        or not turns[0]["result"].get("is_error")
                        or not turns[1]["result"]
                        or turns[1]["result"].get("is_error")):
                    raise AssertionError("blocked tool result or later benign turn behaved incorrectly")
            report = {"test": name, "result": "PASS", **evidence}
            if case_dir is not None:
                (case_dir / "probe-result.json").write_text(
                    json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2),
                    encoding="utf-8")
            print(json.dumps(report, ensure_ascii=False, sort_keys=True), flush=True)
        except Exception as error:
            failed = True
            print(json.dumps({"test": name, "result": "FAIL",
                              "error": f"{type(error).__name__}: {error}"},
                             ensure_ascii=False), file=sys.stderr, flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
