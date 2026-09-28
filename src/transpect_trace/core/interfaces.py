from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Iterable

from .models import TraceEvent


class ClientAdapter(ABC):
    @abstractmethod
    def command(self, *, workspace: Path, prompt: str) -> list[str]:
        raise NotImplementedError

    @abstractmethod
    def parse_event(self, raw: dict[str, Any]) -> Iterable[dict[str, Any]]:
        raise NotImplementedError


class Collector(ABC):
    @abstractmethod
    def start(self) -> None:
        raise NotImplementedError

    @abstractmethod
    def stop(self) -> dict[str, Any]:
        raise NotImplementedError


class Normalizer(ABC):
    @abstractmethod
    def normalize(self, run_dir: Path) -> Iterable[TraceEvent]:
        raise NotImplementedError


class Correlator(ABC):
    @abstractmethod
    def correlate(self, events: list[TraceEvent]) -> list[dict[str, Any]]:
        raise NotImplementedError

