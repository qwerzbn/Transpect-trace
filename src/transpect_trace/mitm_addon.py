"""mitmproxy addon: record decrypted LLM traffic in the Transpect evidence format.

Loaded by `mitmdump -s`. Only hosts in TTRACE_MITM_HOSTS are intercepted; the proxy
records request and response bodies before TLS to the real service. Request credentials
(Authorization, Cookie, api-key, ...) are never written: only accept, content-type and
user-agent headers are kept, matching the existing Gateway recorder.
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
from pathlib import Path

_REPO_SRC = Path(__file__).resolve().parents[1]
if str(_REPO_SRC) not in sys.path:
    sys.path.insert(0, str(_REPO_SRC))

from mitmproxy import http  # noqa: E402

from transpect_trace.core.models import utc_now  # noqa: E402
from transpect_trace.core.storage import TraceBundle  # noqa: E402

KEPT_REQUEST_HEADERS = {"accept", "content-type", "user-agent"}
KEPT_RESPONSE_HEADERS = {"content-type", "x-request-id", "request-id", "openai-request-id"}


class TranscriptRecorder:
    def __init__(self) -> None:
        run_dir = Path(os.environ["TTRACE_RUN_DIR"]).resolve()
        self.run_id = os.environ.get("TTRACE_RUN_ID", run_dir.name)
        self.bundle = TraceBundle(run_dir)
        self.host_pattern = re.compile(os.environ.get("TTRACE_MITM_HOSTS", r".*"))
        self._sequence = 0

    def _record(self, kind: str, **fields: object) -> None:
        self._sequence += 1
        row = {
            "schema": "transpect.raw.gateway/1.0",
            "run_id": self.run_id,
            "collector_seq": self._sequence,
            "captured_at": utc_now(),
            "monotonic_ns": time.monotonic_ns(),
            "capture": "mitmproxy",
            "kind": kind,
            **fields,
        }
        self.bundle.append_jsonl("raw/gateway/events.jsonl", row)

    def _tracked(self, flow: http.HTTPFlow) -> bool:
        return bool(self.host_pattern.search(flow.request.pretty_host))

    def request(self, flow: http.HTTPFlow) -> None:
        if not self._tracked(flow):
            return
        body = flow.request.raw_content or b""
        content = self.bundle.put_blob(
            body,
            media_type=flow.request.headers.get("content-type", "application/octet-stream"),
        )
        flow.metadata["ttrace_request_id"] = flow.id
        self._record(
            "model.request",
            request_id=flow.id,
            method=flow.request.method,
            host=flow.request.pretty_host,
            path=flow.request.path.split("?", 1)[0],
            headers={key.lower(): value for key, value in flow.request.headers.items() if key.lower() in KEPT_REQUEST_HEADERS},
            content=content.model_dump(mode="json"),
        )

    def response(self, flow: http.HTTPFlow) -> None:
        if not self._tracked(flow) or flow.response is None:
            return
        body = flow.response.raw_content or b""
        content = self.bundle.put_blob(
            body,
            media_type=flow.response.headers.get("content-type", "application/octet-stream").split(";", 1)[0],
        )
        self._record(
            "model.response.completed",
            request_id=flow.id,
            status=flow.response.status_code,
            headers={key.lower(): value for key, value in flow.response.headers.items() if key.lower() in KEPT_RESPONSE_HEADERS},
            content=content.model_dump(mode="json"),
        )

    def websocket_message(self, flow: http.HTTPFlow) -> None:
        # Codex account login streams the model conversation over a WebSocket
        # (the responses endpoint answers 101), so the prompt and answer live in frames.
        if not self._tracked(flow) or flow.websocket is None:
            return
        message = flow.websocket.messages[-1]
        payload = message.content if isinstance(message.content, bytes) else str(message.content).encode("utf-8")
        content = self.bundle.put_blob(payload, media_type="application/websocket")
        self._record(
            "model.stream.message",
            request_id=flow.id,
            host=flow.request.pretty_host,
            path=flow.request.path.split("?", 1)[0],
            direction="client_to_server" if message.from_client else "server_to_client",
            content=content.model_dump(mode="json"),
        )

    def error(self, flow: http.HTTPFlow) -> None:
        if not self._tracked(flow):
            return
        self._record(
            "model.request.failed",
            request_id=flow.id,
            host=flow.request.pretty_host,
            path=flow.request.path.split("?", 1)[0],
            reason=str(flow.error) if flow.error else "unknown",
        )


addons = [TranscriptRecorder()]
