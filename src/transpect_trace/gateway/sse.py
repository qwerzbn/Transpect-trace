from __future__ import annotations

from typing import Any


class SSEDecoder:
    """Incremental SSE decoder that tolerates arbitrary transport chunking."""

    def __init__(self) -> None:
        self._buffer = bytearray()

    def feed(self, chunk: bytes) -> list[dict[str, Any]]:
        self._buffer.extend(chunk)
        events: list[dict[str, Any]] = []
        while True:
            lf = self._buffer.find(b"\n\n")
            crlf = self._buffer.find(b"\r\n\r\n")
            candidates = [(lf, 2), (crlf, 4)]
            candidates = [(index, width) for index, width in candidates if index >= 0]
            if not candidates:
                break
            index, width = min(candidates, key=lambda value: value[0])
            block = bytes(self._buffer[:index])
            del self._buffer[: index + width]
            if block:
                events.append(self._parse(block, incomplete=False))
        return events

    def finish(self) -> list[dict[str, Any]]:
        if not self._buffer:
            return []
        block = bytes(self._buffer)
        self._buffer.clear()
        return [self._parse(block, incomplete=True)]

    @staticmethod
    def _parse(block: bytes, *, incomplete: bool) -> dict[str, Any]:
        text = block.decode("utf-8", errors="replace")
        result: dict[str, Any] = {"event": "message", "data": "", "incomplete": incomplete}
        data: list[str] = []
        comments: list[str] = []
        for raw_line in text.replace("\r\n", "\n").split("\n"):
            if raw_line.startswith(":"):
                comments.append(raw_line[1:].lstrip())
                continue
            field, separator, value = raw_line.partition(":")
            if separator and value.startswith(" "):
                value = value[1:]
            if field == "data":
                data.append(value)
            elif field in {"event", "id", "retry"}:
                result[field] = value
        result["data"] = "\n".join(data)
        if comments:
            result["comments"] = comments
        return result

