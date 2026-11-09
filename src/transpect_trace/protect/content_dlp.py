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
from collections import Counter
from dataclasses import dataclass, field
from io import StringIO
from typing import Mapping


MAX_TEXT_BYTES = 16 * 1024 * 1024
INSPECTION_SECONDS = 1.25
BLOCK_THRESHOLD = 0.80
REVIEW_THRESHOLD = 0.50

_EDM_TOKEN = re.compile(r"[A-Za-z0-9_@.+-]{2,128}|[㐀-鿿]{2,128}")
_CHINESE_RUN = re.compile(r"[㐀-鿿]+")
_WORD = re.compile(r"\w+")


@dataclass(frozen=True)
class DLPVerdict:
    decision: str
    reason: str
    rule_ids: tuple[str, ...] = ()
    categories: tuple[str, ...] = ()
    category_scores: Mapping[str, float] = field(default_factory=dict)
    # Deduplicated (category, rule_id, score) triples, so a caller can apply a
    # per-category or per-rule action without re-running inspection. Metadata
    # only: no matched content appears here.
    evidence: tuple[tuple[str, str, float], ...] = ()


@dataclass(frozen=True)
class _Finding:
    category: str
    rule_id: str
    score: float


def _normalize(value: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", value).casefold().split())


def _digest(value: str) -> bytes:
    """Stable 128-bit shingle identity; both index and query use this function.

    BLAKE2b is keyless here on purpose: a shingle index must be comparable
    across restarts. Preimage resistance is what keeps registered document
    text out of the retained index.
    """
    return hashlib.blake2b(value.encode("utf-8"), digest_size=16).digest()


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

    def matches(self, normalized: str, deadline: float) -> list[_Finding]:
        """Scan text already passed through `_normalize`, so tokens need no rework."""
        if not self._digests:
            return []
        hits: dict[str, set[str]] = {}
        candidates: set[str] = set()
        previous = None
        for number, match in enumerate(_EDM_TOKEN.finditer(normalized)):
            if number % 1024 == 0 and time.monotonic() > deadline:
                raise TimeoutError("EDM deadline")
            if number > 200_000 or len(candidates) > 200_000:
                raise ValueError("EDM candidate limit")
            token = match.group()
            candidates.add(token)
            if previous is not None and match.start() - previous.end() == 1:
                candidates.add(previous.group() + " " + token)
            if self._chinese_lengths and _CHINESE_RUN.fullmatch(token):
                for size in self._chinese_lengths:
                    for offset in range(len(token) - size + 1):
                        candidates.add(token[offset:offset + size])
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

    _records: Mapping[str, tuple[str, frozenset[bytes]]] = field(repr=False)

    @classmethod
    def from_documents(cls, documents: Mapping[str, tuple[str, str]]) -> "FingerprintIndex":
        if len(documents) > 4096:
            raise ValueError("fingerprint registration limit")
        records: dict[str, tuple[str, frozenset[bytes]]] = {}
        for registration_id, (category, raw) in documents.items():
            if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", registration_id):
                raise ValueError("invalid registration ID")
            if category not in {"INTERNAL_DOC", "SOURCE_CODE"}:
                raise ValueError("unsupported fingerprint category")
            if len(raw.encode("utf-8")) > MAX_TEXT_BYTES:
                raise ValueError("fingerprint registration size")
            shingles = _shingles(_normalize(raw))
            if len(shingles) < 3:
                raise ValueError("fingerprint registration too short")
            records[registration_id] = (category, frozenset(shingles))
        return cls(records)

    def matches(self, normalized: str, deadline: float) -> list[_Finding]:
        """Scan text already passed through `_normalize`."""
        query = _shingles(normalized, deadline)
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


def _shingles(normalized: str, deadline: float | None = None) -> set[bytes]:
    words = _WORD.findall(normalized)
    if len(words) > 250_000:
        raise ValueError("fingerprint token limit")
    shingles: set[bytes] = set()
    join = " ".join
    for start in range(0, max(0, len(words) - 3), 4096):
        if deadline is not None and time.monotonic() > deadline:
            raise TimeoutError("fingerprint deadline")
        window = words[start:start + 4099]
        shingles.update(_digest(join(window[offset:offset + 4]))
                        for offset in range(len(window) - 3))
    return shingles


def fuse(evidence: tuple[tuple[str, str, float], ...]) -> dict[str, float]:
    """Noisy-OR independent evidence per category; a caller may pass a subset."""
    scores: dict[str, float] = {}
    for category, _rule_id, score in evidence:
        scores[category] = 1 - (1 - scores.get(category, 0.0)) * (1 - score)
    return {category: round(score, 4) for category, score in scores.items()}


def decide(highest: float) -> str:
    return ("BLOCK" if highest >= BLOCK_THRESHOLD
            else "REVIEW" if highest >= REVIEW_THRESHOLD else "ALLOW")


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


def _card_issuer(value: str) -> bool:
    """Luhn alone is weak: one random digit run in ten passes it.

    Requiring a real issuer identification number as well is what separates a
    card from a long version string, epoch stamp or order number. Measured on
    this machine's own prompt history, Luhn-only matching produced 73 denials
    with no card among them.
    """
    digits = "".join(char for char in value if char.isdigit())
    if len(digits) not in {13, 14, 15, 16, 17, 18, 19}:
        return False
    return (digits[0] == "4"                                    # Visa
            or digits[:2] in {"34", "37"}                       # American Express
            or 51 <= int(digits[:2]) <= 55                      # Mastercard
            or 2221 <= int(digits[:4]) <= 2720                  # Mastercard 2-series
            or digits[:2] in {"62", "81"}                       # UnionPay
            or digits[:2] == "35"                               # JCB
            or digits[:4] == "6011" or digits[:2] in {"64", "65"}   # Discover
            or 300 <= int(digits[:3]) <= 305 or digits[:2] in {"36", "38", "39"})


def _card_grouping(value: str) -> bool:
    """Reject separator layouts no card is written in.

    `2265123456-7890` passes Luhn and lands in a Mastercard issuer range, yet
    it is a ten-then-four identifier, not a card. Cards are written contiguous,
    in four-digit groups, or as Amex 4-6-5.
    """
    groups = [len(part) for part in re.split(r"[ -]+", value.strip()) if part]
    if len(groups) == 1:
        return True
    if groups == [4, 6, 5]:
        return True
    return all(size == 4 for size in groups[:-1]) and 1 <= groups[-1] <= 6


def _payment_card(value: str) -> bool:
    return _luhn(value) and _card_issuer(value) and _card_grouping(value)


def _cn_id_valid(value: str) -> bool:
    if not re.fullmatch(r"\d{17}[\dXx]", value):
        return False
    weights = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
    checks = "10X98765432"
    return checks[sum(int(digit) * weight for digit, weight in zip(value[:17], weights)) % 11] == value[-1].upper()


def _credential_body(value: str) -> bool:
    """A real credential body mixes letters and digits and is not a repeat."""
    token = re.split(r"\s+", value.strip())[-1]
    body = token.split("-", 1)[-1] if token.startswith(("sk-", "xox")) else token
    return (any(char.isalpha() for char in body) and any(char.isdigit() for char in body)
            and _entropy(body) >= 3.0)


_ASSIGNED_VALUE = re.compile(r"[=:]\s*['\"]?([A-Za-z0-9+/._=-]{12,})$")
_CODE_REFERENCE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+|[A-Za-z_]+")


def _assigned_value(match_text: str) -> bool:
    """Reject a right-hand side that is code, not a literal.

    In tool output, which is mostly source, `token = self.config.api_token`
    and `password=getpass_prompt` match the assignment shape. A dotted
    reference or a bare identifier with no digit is a name, not a secret.
    Measured on this machine's tool history these two shapes were 741 of the
    rule's hits; a letters-only literal password is the accepted loss.
    """
    match = _ASSIGNED_VALUE.search(match_text)
    return bool(match) and _CODE_REFERENCE.fullmatch(match.group(1)) is None


_PLACEHOLDER_PASSWORDS = frozenset((
    "password", "passwd", "pass", "secret", "changeme", "example", "your_password",
    "yourpassword", "mypassword", "pwd", "123456", "dbpass", "db_password"))


def _url_password(value: str) -> bool:
    match = re.search(r"://[^\s:/@'\"]{1,64}:([^\s@/'\"]{6,128})@", value)
    password = match.group(1) if match else ""
    return (password.casefold() not in _PLACEHOLDER_PASSWORDS
            and not password.startswith(("$", "%", "{", "<")))


# The most frequent Chinese surnames, single and compound. A labeled name must
# start with one; that keeps `客户端`, `员工号` style product words out.
_CN_SURNAMES = frozenset(
    "王李张刘陈杨黄赵吴周徐孙马朱胡郭何高林罗郑梁谢宋唐许韩冯邓曹彭曾肖田董袁潘于蒋蔡余杜叶程苏魏吕丁任沈"
    "姚卢姜崔钟谭陆汪范金石廖贾夏韦付方白邹孟熊秦邱江尹薛闫段雷侯龙史陶黎贺顾毛郝龚邵万钱严覃武戴莫孔向汤"
    "常温康施文牛樊葛邢安齐易乔伍庞颜倪庄聂章鲁岳翟殷詹申欧耿关兰焦俞左柳甘祝包宁尚符舒阮柯纪梅童凌毕单季"
    "裴霍涂成苗谷盛曲翁冉骆蓝路游辛靳管柴蒙鲍华喻祁蒲房滕屈饶解牟艾尤阳时穆农司卓古吉缪简车项连芦麦褚娄"
    "窦戚岑景党宫费卜冷晏席卫米柏宗瞿桂全佟应臧闵苟邬边卞姬师和仇栾隋商刁沙荣巫寇桑郎甄丛仲虞敖巩明佘池"
    "查麻苑迟邝")
_CN_COMPOUND_SURNAMES = ("欧阳", "司马", "诸葛", "上官", "东方", "皇甫", "尉迟", "公孙", "慕容", "令狐", "夏侯", "长孙")


_CN_NAME_LABEL = r"(?:姓名|名字|客户|联系人|收件人|收货人|患者|病人|员工|申请人|持卡人|户名|乘客|学生|业主)"


def _cn_name(value: str) -> bool:
    match = re.fullmatch(_CN_NAME_LABEL + r"\s*[:：为是]?\s*([㐀-鿿]{2,4})", value)
    name = match.group(1) if match else ""
    return bool(name) and (name[0] in _CN_SURNAMES or name.startswith(_CN_COMPOUND_SURNAMES))


_BENIGN = re.compile(r"^(?:[*x•]{3,}|\$\{[^}]+\}|<[^>]+>|placeholder|redacted)$", re.I)
_RULES = (
    ("AWS_ACCESS_KEY", "SECRET", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), 0.95, (), None),
    ("PRIVATE_KEY", "SECRET", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----"), 0.98, (), None),
    # Vendor credentials carry a fixed, documented prefix. A prefix plus the
    # published length is near-certain on its own, so these deny without any
    # surrounding keyword. Before these rules a GitHub or OpenAI token only
    # raised the advisory `ENTROPY_TOKEN` and the gate let it through.
    ("GITHUB_TOKEN", "SECRET", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b"), 0.97, (), None),
    ("OPENAI_API_KEY", "SECRET", re.compile(r"\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}"), 0.96, (), _credential_body),
    ("ANTHROPIC_API_KEY", "SECRET", re.compile(r"\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{40,}"), 0.97, (), None),
    # Legacy OpenAI keys and the `sk-` + 32 hex form several Chinese model
    # vendors (DeepSeek among them) issue. Both still need a credential-shaped body.
    ("SK_API_KEY", "SECRET", re.compile(r"\bsk-(?:[A-Za-z0-9]{48}|[a-f0-9]{32})\b"), 0.92, (), _credential_body),
    ("SLACK_TOKEN", "SECRET", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"), 0.94, (), _credential_body),
    ("GOOGLE_API_KEY", "SECRET", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), 0.94, (), None),
    ("ALIYUN_ACCESS_KEY", "SECRET", re.compile(r"\bLTAI[A-Za-z0-9]{12,20}\b"), 0.92, (), _credential_body),
    ("TENCENT_SECRET_ID", "SECRET", re.compile(r"\bAKID[A-Za-z0-9]{32}\b"), 0.92, (), _credential_body),
    ("STRIPE_SECRET_KEY", "SECRET", re.compile(r"\b[rs]k_live_[A-Za-z0-9]{24,}\b"), 0.96, (), None),
    ("JWT", "SECRET", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), 0.85, (), None),
    ("BEARER_TOKEN", "SECRET", re.compile(r"(?i)\bbearer\s+([A-Za-z0-9._~+/-]{20,}=*)"), 0.88, (), _credential_body),
    # `scheme://user:password@host` -- the password is group 1, so a templated
    # `${DB_PASS}` or `<password>` is dropped by the benign-value check.
    ("URL_PASSWORD", "SECRET", re.compile(r"\b[A-Za-z][A-Za-z0-9+.-]{1,20}://[^\s:/@'\"]{1,64}:([^\s@/'\"]{6,128})@[^\s/'\"]+"), 0.88, (), _url_password),
    # The keyword may sit inside a longer identifier: `aws_secret_access_key=`
    # and `GITHUB_TOKEN=` are the common real spellings, and anchoring the
    # keyword directly against the delimiter missed both.
    ("ASSIGNED_SECRET", "SECRET", re.compile(r"(?i)(?:^|[^A-Za-z0-9])[A-Za-z0-9_.-]{0,40}(?:api[_-]?key|secret|access[_-]?token|client[_-]?secret|token|password|passwd|credential)[A-Za-z0-9_.-]{0,40}\s*[=:]\s*['\"]?([A-Za-z0-9+/._=-]{12,})"), 0.65, ("secret", "token", "password", "key"), _assigned_value),
    ("US_SSN", "PII", re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)"), 0.65, ("ssn", "social security"), None),
    # `(?<!\d\.)`: the fractional digits of a float (`"score": 0.4111111111111111`)
    # pass Luhn and the issuer check about as often as any digit run. They were
    # most card and ID hits in this machine's tool output.
    ("CN_ID", "PII", re.compile(r"(?<!\d)(?<!\d\.)\d{17}[\dXx](?![A-Za-z0-9])"), 0.75, ("身份证", "身份", "证件"), _cn_id_valid),
    ("PAYMENT_CARD", "PII", re.compile(r"(?<!\d)(?<!\d\.)(?:\d[ -]?){13,19}(?!\d)"), 0.88, ("card", "visa", "信用卡", "银行卡", "卡号"), _payment_card),
    ("CN_PASSPORT", "PII", re.compile(r"(?<![A-Za-z0-9])[EG]\d{8}(?![A-Za-z0-9])"), 0.60,
     ("护照", "证件", "签证", "passport"), None),
    ("CN_PHONE", "PII", re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)"), 0.45, ("phone", "mobile", "tel", "电话", "手机", "联系"), None),
    # A labeled Chinese personal name. The label is part of the pattern, so the
    # rule needs no extra context; alone it stays below the REVIEW threshold and
    # only combines with another identifier (noisy-OR) into a denial.
    ("CN_NAME", "PII", re.compile(_CN_NAME_LABEL + r"\s*[:：为是]?\s*([㐀-鿿]{2,4})"), 0.45, (), _cn_name),
    ("CN_ADDRESS", "PII", re.compile(r"(?:[㐀-鿿]{2,8}(?:省|自治区))?[㐀-鿿]{2,8}市[㐀-鿿]{1,8}(?:区|县|市|旗)[㐀-鿿A-Za-z0-9]{0,30}?\d+\s*(?:号|弄|栋|幢|室|单元)"), 0.45, (), None),
    # A boundary prevents the regex engine from retrying at every character
    # inside a long username-like run with no '@' (quadratic backtracking).
    ("EMAIL", "PII", re.compile(r"(?<![\w.+-])[\w.+-]+@[\w-]+\.[\w.-]+"),
     0.35, ("email", "邮箱"), None),
)
_ENTROPY_TOKENS = re.compile(r"[A-Za-z0-9+/=_-]{24,256}")
_HEX = re.compile(r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{2}){16,}(?![0-9a-fA-F])")
_BASE64 = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/])")
_CODE_SIGNALS = tuple(re.compile(expr) for expr in (
    r"\b(?:def|function|class|import|return|public|private|const|let|var)\b",
    r"=>|::|->", r"[;{}]\s*$", r"#include|#define", r"\b(?:if|for|while)\s*\(",
))


# Zero-width and bidi/format characters render as nothing, so `AKIA<ZWSP>...`
# looks like a key to a reader and to the model but not to a regex.
_INVISIBLE = re.compile("[\u00ad\u180e\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff]")
# Shell and JSON escaping that splits a keyword from its value: `\"`, PowerShell
# backtick escapes and cmd carets, plus the quotes themselves, so
# `password=\"value\"` and `"pass""word"=value` reach the rules intact.
_ESCAPES = re.compile(r"""\\(?=["'\\])|`(?=\S)|\^(?=\S)|["']""")


def _normalized_form(text: str) -> str | None:
    """One extra form with width folding, invisibles and shell escapes removed.

    It is a *rewrite* of the same bytes, not a decoding, so findings on it keep
    their plain rule IDs and get no decoded bonus.
    """
    form = _ESCAPES.sub("", _INVISIBLE.sub("", unicodedata.normalize("NFKC", text)))
    return form if form != text else None


def _canonical_forms(text: str, deadline: float) -> list[tuple[str, bool]]:
    """Return (form, decoded) pairs: the text, its normalized rewrite, decodings."""
    forms = [(text, False)]
    normalized = _normalized_form(text)
    if normalized is not None:
        forms.append((normalized, False))
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
            forms.append((decoded, True))
    return forms


def _rules(forms: list[tuple[str, bool]], deadline: float) -> list[_Finding]:
    results = []
    for form, decoded in forms:
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
                if decoded:
                    score += 0.10
                results.append(_Finding(category, rule_id + ("_DECODED" if decoded else ""), min(0.99, score)))
    return results


# Credential-specific phrases, not bare words. "key" alone appears constantly in
# developer prose (primary key, key name, keyboard) and raised the context-entropy
# rate on this machine's own prompt history from 6 to 59 of 2,847 prompts with no
# added true positive.
_ENTROPY_CONTEXT = (
    "api key", "api_key", "api-key", "apikey", "secret", "access key", "access_key",
    "secret key", "secret_key", "private key", "private_key", "token", "credential",
    "credentials", "bearer", "密钥", "令牌", "口令",
)
# Matched as whole words: as substrings, `token` hit `tokenizer/...` paths and
# `max_tokens` in nearly every LLM tool output (3,333 of the context hits on
# this machine's tool history). `_` and `-` still separate words, so
# `access_token` and `x-api-key` keep matching.
_ENTROPY_CONTEXT_RE = re.compile(
    "|".join(rf"(?<![a-z0-9]){re.escape(word)}(?![a-z0-9])" if word.isascii()
             else re.escape(word) for word in _ENTROPY_CONTEXT))


def _entropy_layer(forms: list[tuple[str, bool]], deadline: float) -> list[_Finding]:
    """Run over the decoded forms too: an encoded secret hides from the rules.

    Base64 or hex wrapping leaves a high-entropy blob whose *decoded* value is
    the real credential. Scanning only the original text caught the wrapper by
    luck, never the payload.
    """
    findings = []
    seen = set()
    for form, decoded in forms:
        for number, match in enumerate(_ENTROPY_TOKENS.finditer(form)):
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
                neighborhood = form[max(0, match.start() - 32):match.end() + 32].casefold()
                # A path (`tokenizer/a1b2/...`, three or more separators) or a
                # run longer than the 256-character window is a file name or an
                # encoded blob, not a credential; the context word does not
                # promote it. It is still recorded as uncorroborated entropy.
                context = (token.count("/") < 3 and match.end() - match.start() < 256
                           and not form[match.end():match.end() + 1].isalnum()
                           and _ENTROPY_CONTEXT_RE.search(neighborhood) is not None)
                # Uncorroborated high entropy is reported under its own rule ID.
                # Commit SHAs, package hashes and opaque identifiers all look
                # like this, so a deployment decides whether that alone denies.
                suffix = "_DECODED" if decoded else ""
                findings.append(
                    _Finding("SECRET", "ENTROPY_TOKEN_CONTEXT" + suffix, 0.83)
                    if context else
                    _Finding("SECRET", "ENTROPY_TOKEN" + suffix, 0.60 + 0.25 * decoded))
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
            # Decode base64/hex once; the rule and entropy layers share it.
            forms = _canonical_forms(text, deadline)
            findings = _rules(forms, deadline)
            findings.extend(_entropy_layer(forms, deadline))
            if self.edm_index or self.index:
                # One Unicode normalization pass serves both hash-matching layers.
                normalized = _normalize(text)
                if self.edm_index:
                    findings.extend(self.edm_index.matches(normalized, deadline))
                if self.index:
                    findings.extend(self.index.matches(normalized, deadline))
            findings.extend(_code_layer(text, deadline))
            if time.monotonic() > deadline:
                raise TimeoutError("inspection deadline")
            # Repetition of one weak rule must not manufacture strong evidence.
            unique = {(row.category, row.rule_id): row for row in findings}.values()
            evidence = tuple(sorted((row.category, row.rule_id, round(row.score, 4))
                                    for row in unique))
            scores = fuse(evidence)
            highest = max(scores.values(), default=0.0)
            decision = decide(highest)
            reason = ("MATCHED_SENSITIVE_CONTENT" if decision == "BLOCK"
                      else "AMBIGUOUS_CONTENT" if decision == "REVIEW"
                      else "REQUIRED_CHECKS_COMPLETE")
            return DLPVerdict(decision, reason,
                              tuple(sorted({finding.rule_id for finding in findings})),
                              tuple(sorted(scores)), scores, evidence)
        except Exception:
            return DLPVerdict("BLOCK", "INSPECTION_FAILED", ("INSPECTION_FAILED",),
                              ("INSPECTION_ERROR",),
                              {"INSPECTION_ERROR": 1.0},
                              (("INSPECTION_ERROR", "INSPECTION_FAILED", 1.0),))

    def inspect_file_bytes(self, name: str, data: bytes) -> DLPVerdict:
        # Document parsers are imported on demand: a text-only gate must not pay
        # for a PDF/OOXML stack it never calls.
        from .file_extract import MAX_FILE_BYTES, UninspectableFile, extract_text
        if not isinstance(data, bytes) or len(data) > MAX_FILE_BYTES:
            return DLPVerdict("BLOCK", "FILE_UNINSPECTABLE", ("FILE_UNINSPECTABLE",), ("INSPECTION_ERROR",))
        try:
            text = extract_text(name, data)
        except UninspectableFile:
            return DLPVerdict("BLOCK", "FILE_UNINSPECTABLE", ("FILE_UNINSPECTABLE",), ("INSPECTION_ERROR",))
        except Exception:
            return DLPVerdict("BLOCK", "INSPECTION_FAILED", ("INSPECTION_FAILED",), ("INSPECTION_ERROR",))
        return self.inspect_text(text)
