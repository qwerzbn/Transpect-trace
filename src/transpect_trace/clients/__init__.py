"""Real client adapters."""

from .codex import CodexAdapter
from .claude import ClaudeAdapter

__all__ = ["ClaudeAdapter", "CodexAdapter"]
