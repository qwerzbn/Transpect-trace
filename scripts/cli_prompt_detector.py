"""Local four-layer detector for Codex CLI user-submitted prompt text.

The registered records and document fragments are synthetic examples. This
demo does not inspect files, the assembled model request, or tool traffic.
Lexical and structural checks can miss semantic paraphrases.
"""
from __future__ import annotations

import base64
import binascii
import re
from collections import Counter
from dataclasses import dataclass
from hashlib import sha256
from math import log2

BLOCK_THRESHOLD = 0.80
REVIEW_THRESHOLD = 0.50
_EDM_SALT = b"demo-edm-salt/1"  # per-deployment salt; only hashes are ever compared


# ------------------------------------------------------------------------------------
# Findings and the fused report.
# ------------------------------------------------------------------------------------
@dataclass
class Finding:
    category: str          # SECRET | PII | SOURCE_CODE | INTERNAL_DOC | INSPECTION_ERROR
    layer: str             # which recognition layer fired
    confidence: float
    evidence: str


@dataclass
class Report:
    action: str                    # BLOCK | REVIEW | ALLOW
    category_scores: dict
    findings: list
    source: str = ""


def _action_for(score: float) -> str:
    if score >= BLOCK_THRESHOLD:
        return "BLOCK"
    if score >= REVIEW_THRESHOLD:
        return "REVIEW"
    return "ALLOW"


# ------------------------------------------------------------------------------------
# Shared helpers.
# ------------------------------------------------------------------------------------
def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * log2(c / n) for c in counts.values())


def canonicalize(text: str) -> list:
    """Decode long base64/hex runs so an encoded secret is inspected in plaintext too."""
    out = [text]
    for run in re.findall(r"[A-Za-z0-9+/]{24,}={0,2}", text):
        try:
            decoded = base64.b64decode(run, validate=True).decode("utf-8", "ignore")
        except (binascii.Error, ValueError):
            continue
        if len(decoded) >= 8 and any(ch.isalnum() for ch in decoded):
            out.append(decoded)
    for run in re.findall(r"(?:[0-9a-fA-F]{2}){16,}", text):
        try:
            decoded = bytes.fromhex(run).decode("utf-8", "ignore")
        except ValueError:
            continue
        if len(decoded) >= 8 and any(ch.isalnum() for ch in decoded):
            out.append(decoded)
    return out


def _luhn_ok(digits: str) -> bool:
    nums = [int(d) for d in digits if d.isdigit()]
    if len(nums) < 13:
        return False
    checksum, parity = 0, len(nums) % 2
    for i, d in enumerate(nums):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


_BENIGN_VALUE = re.compile(r"^(?:[*x•]{3,}|\$\{[^}]+\}|<[^>]+>|\.{3,}|placeholder)$", re.I)


# ------------------------------------------------------------------------------------
# Layer (1): rules + validators + context.
# ------------------------------------------------------------------------------------
_RULES = [
    # name, category, pattern, base confidence, context keywords, validator
    ("aws_access_key_id", "SECRET", re.compile(r"AKIA[0-9A-Z]{16}"), 0.90, (), None),
    ("private_key_block", "SECRET",
     re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), 0.97, (), None),
    ("assigned_secret", "SECRET",
     re.compile(r"(?i)(?:secret|api[_-]?key|access[_-]?key|token|password|passwd|pwd)\s*[=:]\s*"
                r"['\"]?([A-Za-z0-9/+._\-]{12,})"), 0.60,
     ("secret", "key", "token", "password", "credential"), None),
    ("us_ssn", "PII", re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), 0.60, ("ssn", "social"), None),
    ("cn_id", "PII", re.compile(r"\b\d{17}[\dXx]\b"), 0.70, ("身份证", "id"), None),
    ("credit_card", "PII", re.compile(r"\b(?:\d[ -]?){13,19}\b"), 0.85,
     ("card", "visa", "mastercard", "信用卡"), _luhn_ok),
    ("cn_phone", "PII", re.compile(r"\b1[3-9]\d{9}\b"), 0.45, ("phone", "mobile", "电话", "手机"), None),
    ("email", "PII", re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+"), 0.35, ("email", "mail", "邮箱"), None),
]


def rules_layer(text: str) -> list:
    findings: list = []
    for candidate in canonicalize(text):
        decoded = candidate is not text
        for name, category, pattern, base_conf, ctx_kw, validator in _RULES:
            for match in pattern.finditer(candidate):
                value = match.group(match.lastindex or 0)
                if _BENIGN_VALUE.match(value.strip()):
                    continue  # masked / placeholder -> not a real secret
                if validator and not validator(match.group(0)):
                    continue
                conf = base_conf
                window = candidate[max(0, match.start() - 30): match.end() + 30].lower()
                if ctx_kw and any(kw in window for kw in ctx_kw):
                    conf = min(0.99, conf + 0.25)
                # An assigned secret whose value is itself high-entropy is very likely real.
                if name == "assigned_secret" and shannon_entropy(value) >= 3.5 and len(value) >= 20:
                    conf = min(0.99, conf + 0.2)
                if decoded:
                    conf = min(0.99, conf + 0.1)  # hidden under encoding -> more suspicious
                findings.append(Finding(category, "rules+context" + ("+canon" if decoded else ""),
                                        round(conf, 2), f"{name}:{match.group(0)[:24]}"))
    return findings


# ------------------------------------------------------------------------------------
# Layer (2): entropy analysis -- unknown-format secrets.
# ------------------------------------------------------------------------------------
def entropy_layer(text: str) -> list:
    findings: list = []
    for token in set(re.findall(r"[A-Za-z0-9+/=_\-]{24,}", text)):
        ent = shannon_entropy(token)
        has_alpha = any(c.isalpha() for c in token)
        has_digit = any(c.isdigit() for c in token)
        if ent >= 3.6 and has_alpha and has_digit:
            # High-entropy blob: a key if a decoded form hits a rule, else possible encoded data.
            decodes_to_secret = any(rules_layer(c) for c in canonicalize(token) if c is not token)
            conf = 0.85 if decodes_to_secret else 0.6
            findings.append(Finding("SECRET", "entropy", conf,
                                     f"high_entropy({ent:.1f}b/char,len={len(token)})"))
    return findings


# ------------------------------------------------------------------------------------
# Layer (3): exact data match (EDM) with corroborative evidence.
# ------------------------------------------------------------------------------------
# Synthetic enterprise records. In production only the salted hashes below ever leave the
# local hashing agent; the raw table is shown here solely to build the demo index.
_EMPLOYEES = [
    {"row": 1, "name": "Zhang Wei", "employee_id": "E10293", "ssn": "123-45-6789",
     "email": "zhang.wei@corp.internal"},
    {"row": 2, "name": "Li Na", "employee_id": "E20481", "ssn": "987-65-4321",
     "email": "li.na@corp.internal"},
]
_FIELD_PATTERNS = {
    "employee_id": re.compile(r"\bE\d{5}\b"),
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "email": re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+"),
}


def _h(value: str) -> str:
    return sha256(_EDM_SALT + value.strip().lower().encode()).hexdigest()


def _build_edm_index():
    index: dict = {}   # hash -> (row, field)
    names: dict = {}   # name_hash -> row  (names matched by scan, not a single pattern)
    for rec in _EMPLOYEES:
        for field_name in ("employee_id", "ssn", "email"):
            index[_h(rec[field_name])] = (rec["row"], field_name)
        names[_h(rec["name"])] = rec["row"]
    return index, names


_EDM_INDEX, _EDM_NAMES = _build_edm_index()


def edm_layer(text: str) -> list:
    hits: dict = {}  # row -> set(fields)
    for field_name, pattern in _FIELD_PATTERNS.items():
        for value in pattern.findall(text):
            entry = _EDM_INDEX.get(_h(value))
            if entry:
                hits.setdefault(entry[0], set()).add(entry[1])
    for name_hash, row in _EDM_NAMES.items():
        for rec in _EMPLOYEES:
            if rec["row"] == row and rec["name"].lower() in text.lower():
                hits.setdefault(row, set()).add("name")
    findings: list = []
    for row, fields in hits.items():
        # Corroboration: one field is weak evidence; several of one record is strong.
        conf = {1: 0.4, 2: 0.85}.get(len(fields), 0.95 if len(fields) >= 3 else 0.4)
        findings.append(Finding("PII", "edm", conf,
                                 f"record_row={row} fields={sorted(fields)}"))
    return findings


# ------------------------------------------------------------------------------------
# Layer (4): document / source-code fingerprint (IDM) + novel-code heuristic.
# ------------------------------------------------------------------------------------
_KNOWN_CORPUS = {
    "INTERNAL_DOC": "Project Nebula confidential roadmap: phase alpha ships the gated egress "
                    "broker, phase beta adds the capability minting service, phase gamma "
                    "delivers the information flow control plane for all internal agents.",
    "SOURCE_CODE": "def rotate_signing_key(tenant_id, kms_client):\n"
                   "    current = kms_client.get_active_key(tenant_id)\n"
                   "    new_key = kms_client.create_key(tenant_id, algorithm='ed25519')\n"
                   "    kms_client.promote(new_key); kms_client.retire(current)\n"
                   "    return new_key.fingerprint",
}
_K = 4


def _shingles(text: str) -> set:
    words = re.findall(r"\w+", text.lower())
    return {sha256(" ".join(words[i:i + _K]).encode("utf-8")).digest()
            for i in range(len(words) - _K + 1)}


_CORPUS_SHINGLES = {cat: _shingles(body) for cat, body in _KNOWN_CORPUS.items()}

_CODE_SIGNALS = [re.compile(p) for p in (
    r"\b(def|function|class|import|return|public|private|const|let|var)\b",
    r"=>|::|->", r"[;{}]\s*$", r"#include|#define", r"\b(if|for|while)\s*\(")]


def fingerprint_layer(text: str) -> list:
    findings: list = []
    query = _shingles(text)
    for category, known in _CORPUS_SHINGLES.items():
        if not query:
            continue
        matched = len(query & known)
        if matched >= 3:
            coverage = matched / len(query)
            findings.append(Finding(category, "fingerprint", round(min(0.97, 0.5 + coverage / 2), 2),
                                     f"known_{category.lower()} shingle_overlap={coverage:.2f}"))
    # Novel source code not in the fingerprint set: structural density heuristic.
    lines = [ln for ln in text.splitlines() if ln.strip()]
    signals = sum(1 for rx in _CODE_SIGNALS if rx.search(text))
    symbol_ratio = sum(text.count(c) for c in "{}();=<>") / max(1, len(text))
    if len(lines) >= 2 and (signals >= 3 or (signals >= 2 and symbol_ratio > 0.03)):
        conf = 0.8 if signals >= 4 else 0.6
        findings.append(Finding("SOURCE_CODE", "code-heuristic", conf,
                                 f"code_signals={signals} symbol_ratio={symbol_ratio:.3f}"))
    return findings


# ------------------------------------------------------------------------------------
# Engine: run every layer, fuse to a per-category score, decide, fail-closed.
# ------------------------------------------------------------------------------------
class ContentDLPEngine:
    LAYERS = (rules_layer, entropy_layer, edm_layer, fingerprint_layer)

    def inspect(self, text: str, source: str = "prompt") -> Report:
        findings: list = []
        for layer in self.LAYERS:
            try:
                findings.extend(layer(text))
            except Exception as error:  # fail-closed: an inspector error must not allow
                findings.append(Finding("INSPECTION_ERROR", layer.__name__, 1.0,
                                         f"{type(error).__name__}: {error}"))
        scores: dict = {}
        for f in findings:
            # Noisy-OR fusion: independent evidence for the same category reinforces.
            prev = scores.get(f.category, 0.0)
            scores[f.category] = round(1 - (1 - prev) * (1 - f.confidence), 2)
        action = "ALLOW"
        for score in scores.values():
            act = _action_for(score)
            if act == "BLOCK" or (act == "REVIEW" and action == "ALLOW"):
                action = act
        return Report(action=action, category_scores=scores, findings=findings, source=source)
