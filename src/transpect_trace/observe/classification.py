"""Deterministic request recognition, independent of risk or enforcement."""
from __future__ import annotations

from typing import Literal
from pydantic import Field
from .models import Record

RULE_VERSION = "llm-requests/1"


class TrafficClassification(Record):
    schema_version: Literal["transpect.observe.classification/1.0"] = "transpect.observe.classification/1.0"
    observation_id: str
    category: Literal["LLM", "NON_LLM", "UNKNOWN"]
    rule_version: str = RULE_VERSION
    evidence: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    can_enforce: Literal[False] = False


def classify(observation_id, value, headers, application, *, complete, decoded=True, empty=False):
    """Paths and application names support a validated payload; neither suffices alone."""
    evidence = []
    limits = []
    if not complete:
        limits.append("request_incomplete")
    if not decoded:
        limits.append("content_not_decoded")
    result = "UNKNOWN"
    path = headers.get(":path", "").split("?",1)[0].rstrip("/")
    method = headers.get(":method", "").upper()
    known_app = application in {"codex-cli", "vscode-codex", "python-api", "chrome-web"}
    if limits:
        return TrafficClassification(observation_id=observation_id, category=result, limitations=limits)
    if isinstance(value, dict):
        model = isinstance(value.get("model"), str) and bool(value["model"])
        inp = value.get("input")
        input_shape = isinstance(inp, str) or (isinstance(inp, list) and bool(inp) and all(
            isinstance(item, dict) and (isinstance(item.get("role"), str) or
                                      isinstance(item.get('type'),str) and item['type'] in {"function_call", "function_call_output", "message"})
            for item in inp))
        messages = value.get("messages")
        chat_shape = isinstance(messages, list) and bool(messages) and all(
            isinstance(item, dict) and isinstance(item.get('role'),str) and item["role"] in {"system", "developer", "user", "assistant", "tool", "function"}
            and ("content" in item or "tool_calls" in item) for item in messages)
        responses_path = path.endswith("/responses")
        chat_path = path.endswith("/chat/completions")
        if value.get("type") == "response.create":
            # Codex uses top-level fields; the public Realtime form uses response.
            nested = value.get("response", value)
            if isinstance(nested, dict) and (isinstance(nested.get("input"), (str, list)) or
                                             isinstance(nested.get("instructions"), str)):
                if known_app or responses_path:
                    result = "LLM"; evidence = ["wss_response_create", "supported_application_or_path"]
        elif model and input_shape and (responses_path or known_app) and method in {"", "POST"}:
            result = "LLM"; evidence = ["responses_payload", "supported_application_or_path"]
        elif model and chat_shape and (chat_path or known_app) and method in {"", "POST"}:
            result = "LLM"; evidence = ["chat_completions_payload", "supported_application_or_path"]
        # Deliberately narrow negative rules; arbitrary JSON stays UNKNOWN.
        elif path in {"/health", "/healthz", "/readyz"} and method == "GET" and set(value) <= {"status", "ok"}:
            result = "NON_LLM"; evidence = ["health_endpoint_and_payload"]
        elif path == "/telemetry" and method == "POST" and isinstance(value.get("events"), list) and set(value) <= {"events", "timestamp"}:
            result = "NON_LLM"; evidence = ["telemetry_endpoint_and_payload"]
    elif value is None and empty and path in {"/health", "/healthz", "/readyz"} and method == "GET":
        result = "NON_LLM"; evidence = ["health_endpoint_without_json"]
    if result == "UNKNOWN":
        limits.append("unrecognized_request_structure")
    return TrafficClassification(observation_id=observation_id, category=result, evidence=evidence, limitations=limits)
