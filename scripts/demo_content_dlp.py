"""Demo: content-recognition DLP for the AI-tool before-send gate.

Goal: identify enterprise-sensitive data in the OUTBOUND prompt text and uploaded files
-- source code, secrets/keys, internal documents, personal information (PII) -- and block
it before it leaves the enterprise boundary. Everything runs LOCALLY (no cloud classifier),
because shipping the content to a third party to classify it is itself a leak ("data
exposure paradox").

Content recognition here is NOT a single regex. It is an ENSEMBLE of complementary layers
fused into a per-category confidence, mirroring modern DLP (Purview / Google Sensitive Data
Protection / Nightfall):

  (1) rules + validators + context  -- regex for well-formed identifiers, a Luhn check to
      cut false positives, and nearby-keyword boosting; base64/hex are canonicalized first
      so cheap encoding dodges are decoded and re-inspected.
  (2) entropy analysis              -- long high-entropy tokens are likely keys/tokens even
      when they match NO known format (catches novel secrets regex cannot).
  (3) exact data match (EDM)        -- the enterprise's own records (employee table) are
      hashed locally; outbound values are matched against the hashes, and CORROBORATIVE
      evidence (several fields of the same record) raises confidence / cuts false positives.
  (4) document & source fingerprint -- k-gram shingles of known internal docs/source detect
      PARTIAL copies even when surrounded by other text or truncated; a structural heuristic
      flags novel source code not in the fingerprint set.

Decisions fuse the layers into BLOCK / REVIEW / ALLOW per category, fail-closed at the
boundary (any inspector error -> BLOCK, never silent allow).

Honest, declared limit (deferred to the next round): a purely SEMANTIC rewrite / paraphrase
of sensitive content is NOT reliably caught by layers (1)-(4). That needs the semantic layer
(embedding similarity / local fine-tuned LLM classifier). The evasion matrix marks those
cases as MISS rather than hiding them.

All secrets, records and documents here are synthetic fakes.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import json
import re
import statistics
import sys
import time
from collections import Counter
from dataclasses import dataclass, field
from hashlib import sha256
from math import log2
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

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
    return {hash(tuple(words[i:i + _K])) for i in range(len(words) - _K + 1)}


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

    def inspect_file(self, path: Path) -> Report:
        raw = path.read_bytes()
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            # Binary / unknown: declared out of scope -> fail-closed to REVIEW, not ALLOW.
            return Report("REVIEW", {"UNSUPPORTED_BINARY": 1.0},
                          [Finding("UNSUPPORTED_BINARY", "file", 1.0,
                                   "non-utf8 upload; OCR/binary parsing out of scope")],
                          source=f"file:{path.name}")
        report = self.inspect(text, source=f"file:{path.name}")
        return report


# ------------------------------------------------------------------------------------
# Scenarios / reporting.
# ------------------------------------------------------------------------------------
_NOVEL_SECRET = "deploytok_xqeF7P2mZk9Lw3Rt8Vb1Nc6Hy4Jd0Gs5Pa2"  # no known format, high entropy

SENSITIVE = [
    ("aws_pair", "SECRET", "aws_access_key_id=AKIAABCDEFGHIJKLMNOP\naws_secret_access_key=Ab3" + "x" * 37),
    ("private_key", "SECRET", "-----BEGIN PRIVATE KEY-----\nMIIFakeKeyMaterial\n-----END PRIVATE KEY-----"),
    ("novel_token", "SECRET", f"here is the deploy token: {_NOVEL_SECRET}"),
    ("internal_doc", "INTERNAL_DOC",
     "FYI quoting our plan: phase beta adds the capability minting service, phase gamma delivers "
     "the information flow control plane for all internal agents. Please review."),
    ("proprietary_code", "SOURCE_CODE", _KNOWN_CORPUS["SOURCE_CODE"]),
    ("pii_corroborated", "PII", "员工 Zhang Wei (E10293), SSN 123-45-6789, 需要报销。"),
]
BENIGN = [
    ("public_text", "请总结这段公开文档的要点，谢谢。"),
    ("code_example_trivial", "A public one-liner example: print('hello world')"),
    ("masked_secret", "password=********"),
    ("placeholder", "api_key=${API_KEY}"),
    ("single_name", "Hi Li, thanks for the update on the public blog post."),
]


def detection_matrix() -> dict:
    engine = ContentDLPEngine()
    rows, blocked, allowed = [], 0, 0
    for name, expected_cat, text in SENSITIVE:
        report = engine.inspect(text)
        hit = report.action in ("BLOCK", "REVIEW") and expected_cat in report.category_scores
        blocked += report.action == "BLOCK"
        rows.append({"case": name, "class": "sensitive", "expected_category": expected_cat,
                     "action": report.action, "scores": report.category_scores,
                     "detected": hit})
    for name, text in BENIGN:
        report = engine.inspect(text)
        allowed += report.action == "ALLOW"
        rows.append({"case": name, "class": "benign", "action": report.action,
                     "scores": report.category_scores})
    return {"sensitive_total": len(SENSITIVE), "sensitive_blocked": blocked,
            "benign_total": len(BENIGN), "benign_allowed": allowed,
            "all_sensitive_caught": all(r.get("detected") for r in rows if r["class"] == "sensitive"),
            "rows": rows}


def evasion_matrix() -> dict:
    engine = ContentDLPEngine()
    secret = "aws_secret_access_key=Ab3" + "x" * 37
    b64 = base64.b64encode(secret.encode()).decode()
    paraphrased_doc = ("Heads up: our upcoming work first ships a gated outbound relay, then a "
                       "service that issues scoped permissions, and finally a data-flow guard.")
    cases = [
        ("plaintext_secret", "none", secret, True, "rules+context"),
        ("base64_encoded_secret", "base64 obfuscation", f"blob: {b64}", True, "canonicalize -> rules"),
        ("novel_format_secret", "unknown key format", f"token {_NOVEL_SECRET}", True, "entropy"),
        ("known_doc_fragment", "partial copy of internal doc",
         "see: phase gamma delivers the information flow control plane for all internal agents",
         True, "fingerprint"),
        ("paraphrased_internal_doc", "semantic rewrite of internal doc", paraphrased_doc,
         False, "MISS -> needs semantic layer (embedding/LLM), deferred"),
    ]
    rows = []
    for name, technique, payload, should_catch, by in cases:
        report = engine.inspect(payload)
        caught = report.action in ("BLOCK", "REVIEW")
        rows.append({"case": name, "technique": technique, "caught": caught,
                     "caught_by": by if caught else by, "action": report.action,
                     "as_expected": caught == should_catch,
                     "honest_note": None if should_catch else
                     "layers (1)-(4) are lexical/structural; pure paraphrase changes the words, "
                     "so only the semantic layer (next round) catches this"})
    return {"total": len(rows), "caught": sum(r["caught"] for r in rows),
            "matrix_as_expected": all(r["as_expected"] for r in rows),
            "misses": [r["case"] for r in rows if not r["caught"]], "rows": rows}


def file_upload_demo() -> dict:
    engine = ContentDLPEngine()
    tmp = ROOT / "runs/demo-io-audit/uploaded_sample.py"
    tmp.parent.mkdir(parents=True, exist_ok=True)
    tmp.write_text(_KNOWN_CORPUS["SOURCE_CODE"] + "\n# config\nAPI_TOKEN = '" + _NOVEL_SECRET + "'\n",
                   encoding="utf-8")
    report = engine.inspect_file(tmp)
    return {"file": tmp.name, "action": report.action, "category_scores": report.category_scores,
            "layers_fired": sorted({f.layer for f in report.findings})}


def latency(iterations: int, payload_kib: int) -> dict:
    engine = ContentDLPEngine()
    filler = "公开文档内容样例。This is public filler text. " * 200
    text = (filler * ((payload_kib * 1024) // len(filler.encode()) + 1))
    text = text.encode()[: payload_kib * 1024].decode("utf-8", "ignore")
    engine.inspect(text)  # warm
    samples = []
    for _ in range(iterations):
        start = time.perf_counter()
        engine.inspect(text)
        samples.append((time.perf_counter() - start) * 1000)
    samples.sort()
    pct = lambda p: samples[min(len(samples) - 1, int(len(samples) * p))]
    return {"iterations": iterations, "payload_kib": payload_kib,
            "p50_ms": round(statistics.median(samples), 3), "p95_ms": round(pct(0.95), 3),
            "p99_ms": round(pct(0.99), 3),
            "note": "local multi-layer inspection only; excludes IPC/TLS"}


def run_scenarios() -> dict:
    detect = detection_matrix()
    evade = evasion_matrix()
    return {"detection": detect, "evasion": evade, "file_upload": file_upload_demo(),
            "structural_controls_pass": detect["all_sensitive_caught"]
            and detect["benign_allowed"] == detect["benign_total"]
            and evade["matrix_as_expected"]}


def main():
    argparse.ArgumentParser(description=__doc__,
                            formatter_class=argparse.RawDescriptionHelpFormatter).parse_args()
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass
    report = run_scenarios()
    d, e, f = report["detection"], report["evasion"], report["file_upload"]
    print("== 内容识别 DLP Demo（本地多层融合 / 发送前）==")
    print(f"[拦截成功率] 敏感 BLOCK {d['sensitive_blocked']}/{d['sensitive_total']}，"
          f"全部敏感被识别={d['all_sensitive_caught']}；良性放行 {d['benign_allowed']}/{d['benign_total']}")
    for row in d["rows"]:
        if row["class"] == "sensitive":
            print(f"   敏感 {row['case']:20s} 动作={row['action']:6s} 命中类别={list(row['scores'])}")
    print(f"[防绕过] 对抗样本 {e['caught']}/{e['total']} 命中（符合预期={e['matrix_as_expected']}）；"
          f"漏检={e['misses']}（纯语义改写，待语义层）")
    for row in e["rows"]:
        print(f"   {row['case']:26s} 命中={row['caught']} 方式={row['caught_by']} 动作={row['action']}")
    print(f"[上传文件] {f['file']} 动作={f['action']} 命中层={f['layers_fired']} 类别={list(f['category_scores'])}")
    lat = latency(300, 64)
    print(f"[性能] P50={lat['p50_ms']}ms P95={lat['p95_ms']}ms P99={lat['p99_ms']}ms (64KiB)")
    print(f"\n结构性控制全部达标: {report['structural_controls_pass']}")
    raise SystemExit(0 if report["structural_controls_pass"] else 1)


if __name__ == "__main__":
    main()
