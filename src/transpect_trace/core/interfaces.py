from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Iterable


class ClientAdapter(ABC):
    @abstractmethod
    def command(self, *, workspace: Path, prompt: str) -> list[str]:
        raise NotImplementedError

    @abstractmethod
    def parse_event(self, raw: dict[str, Any]) -> Iterable[dict[str, Any]]:
        raise NotImplementedError

