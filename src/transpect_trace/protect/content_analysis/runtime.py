"""Lifecycle controller for the native Content Analysis Agent.

This controller intentionally does not install Chrome enterprise policies.
Policy activation is an external, cloud-managed deployment prerequisite.
"""
from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path
import queue
import signal
import subprocess
import threading
import time
from typing import Callable
import re

from .pipe import ContentAnalysisPipeServer
from .policy import ContentAnalysisEngine


class ContentAnalysisRuntime:
    def __init__(
        self,
        *,
        agent: Path,
        chrome: Path,
        engine: ContentAnalysisEngine,
        run_dir: Path,
        allow_sdk_test_client: bool = False,
        ready_timeout_seconds: float = 5.0,
        server_factory: Callable = ContentAnalysisPipeServer,
        popen_factory: Callable = subprocess.Popen,
    ):
        self.agent = Path(agent).resolve()
        self.chrome = Path(chrome).resolve()
        self.engine = engine
        self.run_dir = Path(run_dir).resolve()
        self.allow_sdk_test_client = allow_sdk_test_client
        self.ready_timeout_seconds = ready_timeout_seconds
        self.server_factory = server_factory
        self.popen_factory = popen_factory
        self.server = None
        self.process = None
        self.closed = False
        self.diagnostics: list[str] = []
        self._drain_threads: list[threading.Thread] = []
        self._event_lock = threading.Lock()
        self.native_events: list[dict] = []
        self.status = {
            "schema_version": "transpect.chrome.content.runtime/1.0",
            "state": "created",
            "sdk_provider": "local_user_agent",
            "sdk_path": "path_user",
            "normal_chrome_policy_activation": "external_cloud_policy_required",
            "normal_chrome_can_enforce": False,
            "managed_chrome_policy_changed_by_runtime": False,
            "limitations": [
                "real_managed_chrome_activation_not_attested",
                "cloud_only_connector_policy_not_installed_by_runtime",
            ],
        }

    def command(self, pipe_name: str) -> list[str]:
        command = [
            str(self.agent),
            "--user",
            "--policy-pipe",
            pipe_name,
            "--policy-pid",
            str(os.getpid()),
            "--chrome-path",
            str(self.chrome),
            "--timeout-ms",
            "2000",
        ]
        if self.allow_sdk_test_client:
            command.append("--allow-sdk-test-client")
        return command

    def _write_status(self) -> None:
        target = self.run_dir / "status.json"
        temporary = target.with_suffix(".json.tmp")
        temporary.write_text(
            json.dumps(self.status, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        temporary.replace(target)

    def _read_ready(self) -> dict:
        events: queue.Queue = queue.Queue(maxsize=1)

        def read_line() -> None:
            try:
                line = self.process.stdout.readline()
                if isinstance(line, bytes):
                    line = line.decode("utf-8", errors="strict")
                events.put(json.loads(line))
            except Exception:
                events.put(None)

        threading.Thread(target=read_line, daemon=True).start()
        try:
            event = events.get(timeout=self.ready_timeout_seconds)
        except queue.Empty as error:
            raise RuntimeError("native content agent readiness timed out") from error
        if not isinstance(event, dict) or event.get("event") != "ready":
            raise RuntimeError("native content agent did not attest readiness")
        if event.get("sdk_path") != "path_user":
            raise RuntimeError("native content agent SDK path mismatch")
        self._record_native_event(event)
        return event

    def _record_native_event(self, value: dict) -> None:
        """Persist only the Native Agent's fixed, privacy-safe event vocabulary."""
        allowed = {
            "component",
            "event",
            "pid",
            "trusted",
            "test_mode",
            "request_token_sha256",
            "user_action_id_sha256",
            "status",
            "final_action",
            "result_code",
            "verdict",
            "reason",
            "send_result",
            "sdk_path",
            "sdk_channel",
            "user_specific",
        }
        events = {
            "ready",
            "terminal",
            "startup_failed",
            "browser_connected",
            "browser_disconnected",
            "response_acknowledged",
            "requests_cancelled",
            "request_cancelled",
            "sdk_internal_error",
            "verdict_sent",
            "verdict_failed_closed",
        }
        if set(value) - allowed or value.get("event") not in events:
            return
        for key, item in value.items():
            if isinstance(item, bool) or (key == "pid" and type(item) is int and item > 0):
                continue
            if not isinstance(item, str) or len(item) > 128:
                return
            if key.endswith("_sha256") and not re.fullmatch(r"[a-f0-9]{64}", item):
                return
            if not key.endswith("_sha256") and not re.fullmatch(
                r"[A-Za-z0-9_.:, '()-]{1,128}", item
            ):
                return
        with self._event_lock:
            with (self.run_dir / "native-events.jsonl").open(
                "a", encoding="utf-8"
            ) as output:
                output.write(json.dumps(value, sort_keys=True) + "\n")
                output.flush()
            self.native_events.append(dict(value))

    def _start_output_drains(self) -> None:
        # Never persist arbitrary process output.  Draining both streams keeps
        # a diagnostic burst from blocking the native policy agent.
        def drain_stdout(stream) -> None:
            for line in stream:
                try:
                    value = json.loads(line)
                except (TypeError, ValueError, json.JSONDecodeError):
                    continue
                if isinstance(value, dict):
                    self._record_native_event(value)

        def drain_stderr(stream) -> None:
            for _line in stream:
                pass

        for target, stream in (
            (drain_stdout, self.process.stdout),
            (drain_stderr, self.process.stderr),
        ):
            thread = threading.Thread(
                target=target, args=(stream,), daemon=True
            )
            thread.start()
            self._drain_threads.append(thread)

    def start(self) -> dict:
        if self.process is not None:
            raise RuntimeError("content analysis runtime already started")
        if not self.agent.is_file() or not self.chrome.is_file():
            raise FileNotFoundError("native agent and Chrome executable are required")
        self.run_dir.mkdir(parents=True, exist_ok=False)
        self.status.update(state="initializing", started_at_unix_ns=time.time_ns())
        with self.agent.open("rb") as stream:
            self.status["native_agent_sha256"] = hashlib.file_digest(
                stream, "sha256"
            ).hexdigest()
        with self.chrome.open("rb") as stream:
            self.status["browser_image_sha256"] = hashlib.file_digest(
                stream, "sha256"
            ).hexdigest()
        self._write_status()
        self.server = self.server_factory(
            self.engine, self.run_dir / "audit.jsonl"
        )
        try:
            self.server.start()
            creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            self.process = self.popen_factory(
                self.command(self.server.name),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="strict",
                creationflags=creationflags,
            )
            self.server.set_expected_process(self.process.pid)
            event = self._read_ready()
            self._start_output_drains()
            self.status.update(
                state="sdk_protocol_ready",
                native_agent_pid=self.process.pid,
                native_agent_ready=True,
                native_sdk_path=event["sdk_path"],
                sdk_protocol_gate_ready=True,
                sdk_protocol_can_enforce=False,
                sdk_protocol_certification="not_attested_until_request_round_trip",
            )
            self._write_status()
            return dict(self.status)
        except Exception:
            self.status["state"] = "initialization_failed_fail_closed"
            self._write_status()
            self.close()
            raise

    def update_health(self) -> dict:
        if self.process is None or self.server is None:
            return dict(self.status)
        code = self.process.poll()
        if code is not None or self.server.errors:
            self.status.update(
                state="degraded_fail_closed",
                native_agent_exit_code=code,
                policy_service_error_count=len(self.server.errors),
            )
            self._write_status()
        return dict(self.status)

    def attest_controlled_protocol(self, expected_requests: int) -> dict:
        """Certify only the SDK test-client round trip, never normal Chrome."""
        if not self.allow_sdk_test_client or self.server is None:
            raise RuntimeError("controlled SDK attestation is not enabled")
        audits = list(self.server.records)
        acknowledgements = [
            event
            for event in self.native_events
            if event.get("event") == "response_acknowledged"
        ]
        if len(audits) != expected_requests or len(acknowledgements) != expected_requests:
            raise RuntimeError("controlled SDK evidence count mismatch")
        expected = {
            row["request_token_sha256"]: row["decision"] for row in audits
        }
        actual = {
            row["request_token_sha256"]: row["final_action"]
            for row in acknowledgements
            if row.get("status") == "SUCCESS"
        }
        if len(expected) != expected_requests or expected != actual or not {
            "ALLOW",
            "BLOCK",
        }.issubset(set(expected.values())):
            raise RuntimeError("controlled SDK verdict acknowledgement mismatch")
        self.status.update(
            sdk_protocol_can_enforce=True,
            sdk_protocol_certification="controlled_sdk_client_round_trip",
            sdk_protocol_attested_requests=expected_requests,
        )
        self._write_status()
        return dict(self.status)

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        cleanup_errors: list[str] = []
        if self.process is not None and self.process.poll() is None:
            try:
                if hasattr(signal, "CTRL_BREAK_EVENT"):
                    self.process.send_signal(signal.CTRL_BREAK_EVENT)
                else:
                    self.process.terminate()
                self.process.wait(timeout=5)
            except Exception:
                cleanup_errors.append("native_agent_terminate_failed")
                try:
                    self.process.terminate()
                    self.process.wait(timeout=2)
                except Exception:
                    cleanup_errors.append("native_agent_terminate_fallback_failed")
                    try:
                        self.process.kill()
                        self.process.wait(timeout=2)
                    except Exception:
                        cleanup_errors.append("native_agent_kill_failed")
        if self.server is not None:
            try:
                self.server.close()
            except Exception:
                cleanup_errors.append("policy_service_close_failed")
        prior_state = self.status.get("state", "unknown")
        terminal_state = (
            prior_state
            if "failed" in prior_state or "degraded" in prior_state
            else "stopped"
        )
        self.status.update(
            state=(
                terminal_state
                if not cleanup_errors
                else "cleanup_incomplete_fail_closed"
            ),
            ended_at_unix_ns=time.time_ns(),
            cleanup_errors=cleanup_errors,
        )
        if self.run_dir.exists():
            self._write_status()

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, _type, _value, _traceback):
        self.close()
