"""One-time user approval for a REVIEW denial.

`REVIEW` means "ambiguous": a hit that is often legitimate. Denying it with no
way forward makes a gate unusable, so a REVIEW denial carries a short code and
the user can approve that exact content once:

* a prompt: append `#dlp-approve <CODE> <理由>` to the same prompt and resend;
* a tool call or tool output: reply `#dlp-approve <CODE> <理由>`, then let the
  agent retry the same call.

Rules that keep this from becoming a bypass:

* `BLOCK` is never overridable; only an actionable `REVIEW` issues a code.
* A code is bound to a keyed digest of the exact content (prompt text, or tool
  name plus arguments), to the session, and to the event kind. Different bytes
  or another session do not match.
* Only `UserPromptSubmit` text redeems or grants a code. The model sees tool
  codes in the denial reason but cannot type a user prompt.
* Codes expire (default 10 minutes) and are single use; consumption is an
  atomic rename, so two concurrent hook processes cannot both use one code.

State holds digests and timestamps only. The key is local and random, so a
digest cannot be checked against guessed content by someone without it.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import time

APPROVAL_LINE = re.compile(r"(?m)^[ \t]*#dlp-approve[ \t]+([A-Z2-9]{6})[ \t]*(.*?)[ \t]*$")
_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
MAX_PENDING = 512


@dataclass(frozen=True)
class Approval:
    code: str
    justification: str


def split_approvals(prompt: str) -> tuple[str, list[Approval]]:
    """Return the prompt without approval lines, plus the approvals it carried."""
    approvals = [Approval(match.group(1), match.group(2).strip())
                 for match in APPROVAL_LINE.finditer(prompt)]
    stripped = APPROVAL_LINE.sub("", prompt).strip("\r\n")
    return stripped, approvals


class OverrideStore:
    def __init__(self, directory: Path, ttl_seconds: int):
        if not isinstance(ttl_seconds, int) or not 0 < ttl_seconds <= 86_400:
            raise ValueError("override TTL must be 1..86400 seconds")
        self.directory = Path(directory)
        self.ttl = ttl_seconds
        self._key_cache: bytes | None = None

    # ---- storage ----
    def _key(self) -> bytes:
        if self._key_cache is None:
            path = self.directory / "override.key"
            self.directory.mkdir(parents=True, exist_ok=True)
            try:
                with open(path, "xb") as stream:
                    stream.write(secrets.token_bytes(32))
            except FileExistsError:
                pass
            key = path.read_bytes()
            if len(key) != 32:
                raise ValueError("invalid override key")
            self._key_cache = key
        return self._key_cache

    def digest(self, kind: str, session_id: str, content: str) -> str:
        message = json.dumps([kind, session_id, content], ensure_ascii=False).encode("utf-8")
        return hmac.new(self._key(), message, hashlib.sha256).hexdigest()

    def _pending(self) -> Path:
        path = self.directory / "pending"
        path.mkdir(parents=True, exist_ok=True)
        return path

    def _write(self, path: Path, record: dict) -> None:
        temporary = path.with_suffix(f".{secrets.token_hex(4)}.tmp")
        temporary.write_text(json.dumps(record), encoding="utf-8")
        os.replace(temporary, path)

    def _load(self, code: str) -> dict | None:
        if not re.fullmatch(r"[A-Z2-9]{6}", code):
            return None
        path = self._pending() / f"{code}.json"
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        if record.get("expires_at", 0) < time.time():
            path.unlink(missing_ok=True)
            return None
        return record

    def _consume(self, code: str) -> bool:
        """Atomically remove a code; only one caller can succeed."""
        source = self._pending() / f"{code}.json"
        used = self.directory / "used"
        used.mkdir(parents=True, exist_ok=True)
        try:
            os.replace(source, used / f"{code}.{secrets.token_hex(4)}.json")
        except FileNotFoundError:
            return False
        return True

    def _prune(self) -> None:
        now = time.time()
        entries = sorted(self._pending().glob("*.json"), key=lambda p: p.stat().st_mtime)
        for path in entries:
            try:
                if json.loads(path.read_text(encoding="utf-8")).get("expires_at", 0) < now:
                    path.unlink(missing_ok=True)
            except (OSError, ValueError):
                path.unlink(missing_ok=True)
        entries = sorted(self._pending().glob("*.json"), key=lambda p: p.stat().st_mtime)
        for path in entries[:max(0, len(entries) - MAX_PENDING)]:
            path.unlink(missing_ok=True)
        for path in (self.directory / "used").glob("*.json"):
            if path.stat().st_mtime < now - 7 * 86_400:
                path.unlink(missing_ok=True)

    # ---- protocol ----
    def issue(self, kind: str, session_id: str, content: str) -> str:
        """Record a pending approval for this exact content and return its code."""
        self._prune()
        record = {"kind": kind, "digest": self.digest(kind, session_id, content),
                  "session_id_digest": self.digest("session", "", session_id),
                  "issued_at": time.time(), "expires_at": time.time() + self.ttl,
                  "granted": False}
        for _ in range(16):
            code = "".join(secrets.choice(_ALPHABET) for _ in range(6))
            path = self._pending() / f"{code}.json"
            if not path.exists():
                self._write(path, record)
                return code
        raise RuntimeError("could not allocate an override code")

    def grant(self, code: str, session_id: str) -> str | None:
        """A user prompt approves a pending *tool* code; return its kind."""
        record = self._load(code)
        if (record is None or record["kind"] == "UserPromptSubmit"
                or record["session_id_digest"] != self.digest("session", "", session_id)):
            return None
        record.update(granted=True, expires_at=time.time() + self.ttl)
        self._write(self._pending() / f"{code}.json", record)
        return record["kind"]

    def redeem_prompt(self, code: str, session_id: str, content: str) -> bool:
        record = self._load(code)
        if (record is None or record["kind"] != "UserPromptSubmit"
                or not hmac.compare_digest(record["digest"],
                                           self.digest("UserPromptSubmit", session_id, content))):
            return False
        return self._consume(code)

    def redeem_tool(self, kind: str, session_id: str, content: str) -> str | None:
        """Consume a granted code bound to this tool content; return the code."""
        digest = self.digest(kind, session_id, content)
        for path in self._pending().glob("*.json"):
            code = path.stem
            record = self._load(code)
            if (record and record["kind"] == kind and record.get("granted")
                    and hmac.compare_digest(record["digest"], digest)
                    and self._consume(code)):
                return code
        return None
