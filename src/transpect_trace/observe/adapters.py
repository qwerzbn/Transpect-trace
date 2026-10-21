"""Truthful eCapture routing: SSPI plaintext and Codex request-layer snapshots.

Routing unifies management, not provenance. Selecting codex-request does not
certify Schannel or any TLS backend and never installs another Guard Hook.
"""
from __future__ import annotations

from transpect_trace.guard import BINARY_SHA256


def capability(adapter: str, *, protection=False):
    if adapter not in {"schannel", "codex-request"}:
        raise ValueError("unknown eCapture observation adapter")
    request = adapter == "codex-request"
    return dict(adapter=adapter, capture_layer="request-body" if request else "tls-plaintext",
        collector="ecapture", implementation="native-guard-tap" if request and protection else
            "native-observer" if request else "ecapture-windows-sspi",
        protocols=["http-json", "verified-wss-message"] if request else ["http/1.1", "http/2", "verified-wss"],
        maximum_request_bytes=16 * 1024 * 1024, can_enforce=False,
        tls_plaintext_capture=not request, hook_owner="native-guard" if request and protection else
            "native-observer" if request else "ecapture-windows",
        limitations=["Observation is independent from sending and actual request rejection",
                     "Request adapter does not establish TLS-backend support"] if request else
            ["Only verified SSPI application-data paths; not every Windows TLS implementation"])


def create_collector(adapter, subject, profile, *, pipeline, dll=None, ecapture=None, protection=False, elevate=False):
    """Return an explicit observer; never silently fall back after capture loss."""
    capability(adapter, protection=protection)
    if adapter == "codex-request":
        if subject.get("image_sha256") != BINARY_SHA256 or profile.application != "codex-cli" or profile.mode != "codex-json":
            raise ValueError("Codex request adapter requires the fixed official baseline")
        if protection:
            from .request_capture import GuardRequestTap
            return GuardRequestTap(pipeline.directory, subject, pipeline=pipeline)
        if dll is None:
            raise ValueError("Codex request observation requires a Native Observer DLL")
        from .native import NativeCollector
        return NativeCollector(subject, profile, dll, pipeline)
    if protection:
        raise ValueError("Schannel eCapture cannot own request protection")
    if ecapture is None or profile.mode != "schannel":
        raise ValueError("Schannel eCapture requires a verified SSPI profile and collector")
    from .ecapture import ECaptureCollector
    return ECaptureCollector(subject, profile, ecapture, pipeline, elevate=elevate)
