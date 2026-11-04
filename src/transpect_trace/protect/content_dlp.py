"""Local four-layer content recognition for synchronous outbound gates.

The returned verdict contains rule IDs and category scores, never matched
content.  Scores are deterministic decision weights, not leak probabilities.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import math
import re
import time
import unicodedata
from collections import Counter, deque
from dataclasses import dataclass, field
from io import StringIO
from typing import Mapping

from .file_extract import MAX_FILE_BYTES, UninspectableFile, extract_text


MAX_TEXT_BYTES = 16 * 1024 * 1024
INSPECTION_SECONDS = 1.25
BLOCK_THRESHOLD = 0.80
REVIEW_THRESHOLD = 0.50


@dataclass(frozen=True)
class DLPVerdict:
    decision: str
    reason: str
    rule_ids: tuple[str, ...] = ()
    categories: tuple[str, ...] = ()
    category_scores: Mapping[str, float] = field(default_factory=dict)


@dataclass(frozen=True)
class _Finding:
    category: str
    rule_id: str
    score: float


def _normalize(value: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", value).casefold().split())


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class EDMIndex:
    """Hash-only record index; the secret HMAC key stays in the local process."""

    _key: bytes = field(repr=False)
    _digests: Mapping[str, tuple[tuple[str, str], ...]] = field(repr=False)
    _chinese_lengths: frozenset[int] = field(repr=False)

    @classmethod
    def from_records(cls, records: Mapping[str, Mapping[str, str]], key: bytes) -> "EDMIndex":
        if not isinstance(key, bytes) or len(key) < 32:
            raise ValueError("EDM HMAC key must have at least 32 bytes")
        if len(records) > 4096:
            raise ValueError("EDM record limit")
        values: dict[str, list[tuple[str, str]]] = {}
        chinese_lengths: set[int] = set()
        for record_id, fields in records.items():
            if not record_id or not fields or len(fields) > 32:
                raise ValueError("invalid EDM record")
            for field_name, raw in fields.items():
                if not field_name or not isinstance(raw, str):
                    raise ValueError("invalid EDM field")
                normalized = _normalize(raw)
                if not 2 <= len(normalized) <= 128:
                    raise ValueError("EDM value length")
                value_hash = hmac.new(key, normalized.encode("utf-8"), hashlib.sha256).hexdigest()
                values.setdefault(value_hash, []).append((str(record_id), field_name))
                if re.fullmatch(r"[\u3400-\u9fff]{2,8}", normalized):
                    chinese_lengths.add(len(normalized))
        return cls(bytes(key), {digest: tuple(rows) for digest, rows in values.items()}, frozenset(chinese_lengths))

    def matches(self, text: str, deadline: float) -> list[_Finding]:
        if not self._digests:
            return []
        hits: dict[str, set[str]] = {}
        candidates: set[str] = set()
        token_pattern = re.compile(r"[A-Za-z0-9_@.+-]{2,128}|[\u3400-\u9fff]{2,128}")
        previous = None
        for number, match in enumerate(token_pattern.finditer(text)):
            if number % 1024 == 0 and time.monotonic() > deadline:
                raise TimeoutError("EDM deadline")
            if number > 200_000:
                raise ValueError("EDM candidate limit")
            candidates.add(_normalize(match.group()))
            if previous is not None and match.start() - previous.end() <= 3 and text[previous.end():match.start()].isspace():
                candidates.add(_normalize(previous.group() + " " + match.group()))
            if self._chinese_lengths and re.fullmatch(r"[\u3400-\u9fff]+", match.group()):
                chinese = match.group()
                for size in self._chinese_lengths:
                    for offset in range(len(chinese) - size + 1):
                        candidates.add(_normalize(chinese[offset:offset + size]))
                        if len(candidates) > 200_000:
                            raise ValueError("EDM candidate limit")
            previous = match
        for number, candidate in enumerate(candidates):
            if number % 1024 == 0 and time.monotonic() > deadline:
                raise TimeoutError("EDM deadline")
            digest = hmac.new(self._key, candidate.encode("utf-8"), hashlib.sha256).hexdigest()
            for record_id, field_name in self._digests.get(digest, ()):
                hits.setdefault(record_id, set()).add(field_name)
        findings = []
        for fields in hits.values():
            score = 0.95 if len(fields) >= 3 else 0.88 if len(fields) == 2 else 0.40
            findings.append(_Finding("PII", "EDM_CORROBORATED" if len(fields) >= 2 else "EDM_SINGLE_FIELD", score))
        return findings


@dataclass(frozen=True)
class FingerprintIndex:
    """Stable SHA-256 four-word shingles; no registered document text is retained."""

    _records: Mapping[str, tuple[str, frozenset[str]]] = field(repr=False)

    @classmethod
    def from_documents(cls, documents: Mapping[str, tuple[str, str]]) -> "FingerprintIndex":
        if len(documents) > 4096:
            raise ValueError("fingerprint registration limit")
        records: dict[str, tuple[str, frozenset[str]]] = {}
        for registration_id, (category, raw) in documents.items():
            if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", registration_id):
                raise ValueError("invalid registration ID")
            if category not in {"INTERNAL_DOC", "SOURCE_CODE"}:
                raise ValueError("unsupported fingerprint category")
            if len(raw.encode("utf-8")) > MAX_TEXT_BYTES:
                raise ValueError("fingerprint registration size")
            shingles = _shingles(raw)
            if len(shingles) < 3:
                raise ValueError("fingerprint registration too short")
            records[registration_id] = (category, frozenset(shingles))
        return cls(records)

    def matches(self, text: str, deadline: float) -> list[_Finding]:
        query = _shingles(text, deadline)
        findings = []
        for registration_id, (category, registered) in self._records.items():
            if time.monotonic() > deadline:
                raise TimeoutError("fingerprint deadline")
            overlap = len(query & registered)
            if overlap >= 3:
                coverage = overlap / max(1, min(len(query), len(registered)))
                score = min(0.98, 0.75 + 0.23 * coverage)
                findings.append(_Finding(category, f"FINGERPRINT:{registration_id}", score))
        return findings


def _shingles(text: str, deadline: float | None = None) -> set[str]:
    words: deque[str] = deque(maxlen=4)
    shingles = set()
    for offset, match in enumerate(re.finditer(r"\w+", _normalize(text))):
        if offset > 250_000:
            raise ValueError("fingerprint token limit")
        if offset % 4096 == 0 and deadline is not None and time.monotonic() > deadline:
            raise TimeoutError("fingerprint deadline")
        words.append(match.group())
        if len(words) == 4:
            shingles.add(_digest(" ".join(words)))
    return shingles


def _entropy(token: str) -> float:
    frequencies = Counter(token)
    size = len(token)
    return -sum((count / size) * math.log2(count / size) for count in frequencies.values())


def _luhn(value: str) -> bool:
    digits = [int(char) for char in value if char.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    return sum((digit * 2 - 9 if digit * 2 > 9 else digit * 2) if offset % 2 else digit
               for offset, digit in enumerate(reversed(digits))) % 10 == 0


def _cn_id_valid(value: str) -> bool:
    if not re.fullmatch(r"\d{17}[\dXx]", value):
        return False
    weights = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
    checks = "10X98765432"
    return checks[sum(int(digit) * weight for digit, weight in zip(value[:17], weights)) % 11] == value[-1].upper()


_BENIGN = re.compile(r"^(?:[*x•]{3,}|\$\{[^}]+\}|<[^>]+>|placeholder|redacted)$", re.I)
_RULES = (
    ("AWS_ACCESS_KEY", "SECRET", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), 0.95, (), None),
    ("PRIVATE_KEY", "SECRET", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), 0.98, (), None),
    ("ASSIGNED_SECRET", "SECRET", re.compile(r"(?i)\b(?:api[_-]?key|secret|access[_-]?token|client_secret|token|password|passwd)\s*[=:]\s*['\"]?([A-Za-z0-9+/._=-]{12,})"), 0.65, ("secret", "token", "password", "key"), None),
    ("US_SSN", "PII", re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)"), 0.65, ("ssn", "social security"), None),
    ("CN_ID", "PII", re.compile(r"(?<!\d)\d{17}[\dXx](?![A-Za-z0-9])"), 0.75, ("身份证", "身份", "证件"), _cn_id_valid),
    ("PAYMENT_CARD", "PII", re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)"), 0.88, ("card", "visa", "信用卡", "银行卡"), _luhn),
    ("CN_PASSPORT", "PII", re.compile(r"(?<![A-Za-z0-9])[EG]\d{8}(?![A-Za-z0-9])"), 0.60,
     ("护照", "证件", "签证", "passport"), None),
    ("CN_PHONE", "PII", re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)"), 0.45, ("phone", "mobile", "电话", "手机"), None),
    ("EMAIL", "PII", re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+"), 0.35, ("email", "邮箱"), None),
)
_ENTROPY_TOKENS = re.compile(r"[A-Za-z0-9+/=_-]{24,256}")
_HEX = re.compile(r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{2}){16,}(?![0-9a-fA-F])")
_BASE64 = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/])")
_CODE_SIGNALS = tuple(re.compile(expr) for expr in (
    r"\b(?:def|function|class|import|return|public|private|const|let|var)\b",
    r"=>|::|->", r"[;{}]\s*$", r"#include|#define", r"\b(?:if|for|while)\s*\(",
))


def _canonical_forms(text: str, deadline: float) -> list[str]:
    forms = [text]
    consumed = 0
    for expression, hex_mode in ((_HEX, True), (_BASE64, False)):
        for number, match in enumerate(expression.finditer(text)):
            if number % 256 == 0 and time.monotonic() > deadline:
                raise TimeoutError("decode deadline")
            token = match.group()
            if len(token) > 262_144:
                raise ValueError("encoded token limit")
            try:
                data = bytes.fromhex(token) if hex_mode else base64.b64decode(token, validate=True)
                decoded = data.decode("utf-8")
            except (ValueError, UnicodeDecodeError, binascii.Error):
                continue
            if len(decoded) < 8 or not any(char.isalnum() for char in decoded):
                continue
            consumed += len(data)
            if consumed > 1024 * 1024:
                raise ValueError("decoded content limit")
            forms.append(decoded)
    return forms


def _rules(text: str, deadline: float) -> list[_Finding]:
    results = []
    for form_index, form in enumerate(_canonical_forms(text, deadline)):
        for rule_id, category, pattern, base, context, validator in _RULES:
            for number, match in enumerate(pattern.finditer(form)):
                if number % 1024 == 0 and time.monotonic() > deadline:
                    raise TimeoutError("rules deadline")
                value = match.group(match.lastindex or 0)
                if _BENIGN.fullmatch(value.strip()):
                    continue
                neighborhood = form[max(0, match.start() - 32):match.end() + 32].casefold()
                contextual = any(keyword in neighborhood for keyword in context)
                if validator and not validator(match.group(0).strip()):
                    # Synthetic data and OCR often contain invalid check digits. A
                    # labeled, well-shaped value still merits a denied REVIEW.
                    if contextual and rule_id in {"CN_ID", "PAYMENT_CARD"}:
                        results.append(_Finding(category, rule_id + "_CONTEXT_UNVERIFIED", 0.55))
                    continue
                score = base + (0.20 if contextual else 0)
                if rule_id == "ASSIGNED_SECRET" and len(value) >= 20 and _entropy(value) >= 3.5:
                    score += 0.15
                if form_index:
                    score += 0.10
                results.append(_Finding(category, rule_id + ("_DECODED" if form_index else ""), min(0.99, score)))
    return results


def _entropy_layer(text: str, deadline: float) -> list[_Finding]:
    findings = []
    seen = set()
    for number, match in enumerate(_ENTROPY_TOKENS.finditer(text)):
        if number % 1024 == 0 and time.monotonic() > deadline:
            raise TimeoutError("entropy deadline")
        token = match.group()
        if token in seen:
            continue
        seen.add(token)
        if len(seen) > 65_536:
            raise ValueError("entropy token limit")
        if re.fullmatch(r"[a-fA-F0-9]{32,128}", token):
            continue  # Common checksums, handled by rules if context identifies a secret.
        if not (any(char.isalpha() for char in token) and any(char.isdigit() for char in token)):
            continue
        if _entropy(token) >= 3.6:
            neighborhood = text[max(0, match.start() - 32):match.end() + 32].casefold()
            context = any(word in neighborhood for word in ("token", "secret", "key", "credential", "密钥", "令牌"))
            findings.append(_Finding("SECRET", "ENTROPY_TOKEN", 0.83 if context else 0.60))
    return findings


def _code_layer(text: str, deadline: float) -> list[_Finding]:
    if time.monotonic() > deadline:
        raise TimeoutError("code deadline")
    nonempty_lines = 0
    for line in StringIO(text):
        nonempty_lines += bool(line.strip())
        if nonempty_lines >= 2:
            break
    if nonempty_lines < 2:
        return []
    signals = sum(bool(pattern.search(text)) for pattern in _CODE_SIGNALS)
    symbol_ratio = sum(text.count(char) for char in "{}();=<>") / max(1, len(text))
    if signals >= 4:
        return [_Finding("SOURCE_CODE", "CODE_STRUCTURE", 0.85)]
    if signals >= 2 and symbol_ratio > 0.03:
        return [_Finding("SOURCE_CODE", "CODE_STRUCTURE", 0.60)]
    return []


class ContentDLPEngine:
    """Inspect immutable text or file bytes with the same local four-layer policy."""

    def __init__(self, index: FingerprintIndex | None = None, edm_index: EDMIndex | None = None):
        self.index = index
        self.edm_index = edm_index

    def inspect_text(self, text: str) -> DLPVerdict:
        if not isinstance(text, str) or len(text.encode("utf-8")) > MAX_TEXT_BYTES:
            return DLPVerdict("BLOCK", "TEXT_UNINSPECTABLE", ("TEXT_UNINSPECTABLE",), ("INSPECTION_ERROR",))
        deadline = time.monotonic() + INSPECTION_SECONDS
        try:
            findings = _rules(text, deadline)
            findings.extend(_entropy_layer(text, deadline))
            if self.edm_index:
                findings.extend(self.edm_index.matches(text, deadline))
            if self.index:
                findings.extend(self.index.matches(text, deadline))
            findings.extend(_code_layer(text, deadline))
            if time.monotonic() > deadline:
                raise TimeoutError("inspection deadline")
            scores: dict[str, float] = {}
            # Repetition of one weak rule must not manufacture strong evidence.
            for finding in {(row.category, row.rule_id): row for row in findings}.values():
                previous = scores.get(finding.category, 0.0)
                scores[finding.category] = 1 - (1 - previous) * (1 - finding.score)
            highest = max(scores.values(), default=0.0)
            decision = "BLOCK" if highest >= BLOCK_THRESHOLD else "REVIEW" if highest >= REVIEW_THRESHOLD else "ALLOW"
            reason = "MATCHED_SENSITIVE_CONTENT" if decision == "BLOCK" else "AMBIGUOUS_CONTENT" if decision == "REVIEW" else "REQUIRED_CHECKS_COMPLETE"
            return DLPVerdict(decision, reason,
                              tuple(sorted({finding.rule_id for finding in findings})),
                              tuple(sorted(scores)),
                              {key: round(value, 4) for key, value in scores.items()})
        except Exception:
            return DLPVerdict("BLOCK", "INSPECTION_FAILED", ("INSPECTION_FAILED",), ("INSPECTION_ERROR",))

    def inspect_file_bytes(self, name: str, data: bytes) -> DLPVerdict:
        if not isinstance(data, bytes) or len(data) > MAX_FILE_BYTES:
            return DLPVerdict("BLOCK", "FILE_UNINSPECTABLE", ("FILE_UNINSPECTABLE",), ("INSPECTION_ERROR",))
        try:
            text = extract_text(name, data)
        except UninspectableFile:
            return DLPVerdict("BLOCK", "FILE_UNINSPECTABLE", ("FILE_UNINSPECTABLE",), ("INSPECTION_ERROR",))
        except Exception:
            return DLPVerdict("BLOCK", "INSPECTION_FAILED", ("INSPECTION_FAILED",), ("INSPECTION_ERROR",))
        return self.inspect_text(text)
