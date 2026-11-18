"""Content policy shared by the Claude Code in-process and proxy transports."""
from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .native_collection import NativeCollectionEngine


def create_claude_engine(run_dir: Path) -> NativeCollectionEngine:
    """Deny sensitive turns and allow verified history recovery on later turns."""
    from .codex_hook_gate import GateConfig
    from .native_collection import NativeCollectionEngine

    config = GateConfig(
        mode="enforce",
        archive_directory=run_dir / "archive",
        audit_file=run_dir / "audit.jsonl",
        registration_directory=None,
        review_override_ttl_seconds=0,
        collection_file=run_dir / "collection.jsonl",
        redact_on_block=False,
    )
    engine = NativeCollectionEngine(
        config,
        archive_full_body=True,
        shared_request_archive=True,
        allowed_formats=frozenset({"anthropic_messages"}),
        scrub_denied_history=True,
    )
    engine.concurrent_safe = True
    return engine
