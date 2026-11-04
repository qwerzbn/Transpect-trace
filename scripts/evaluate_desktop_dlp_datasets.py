"""Local, reproducible evaluation on public synthetic PII corpora.

First run fetches SHA-pinned corpora; inspection itself is fully local.
Run: uv run --no-sync --with duckdb==2.0.0 python scripts/evaluate_desktop_dlp_datasets.py
No corpus text is written to the report or sent to a classifier.
"""
from __future__ import annotations

import argparse
import ast
from collections import Counter, defaultdict
import hashlib
from html import escape
from io import BytesIO
import json
from pathlib import Path
import time
from urllib.request import urlopen
from zipfile import ZipFile, ZipInfo

from pypdf import PdfWriter
from pypdf.generic import DecodedStreamObject, DictionaryObject, NameObject
from transpect_trace.protect.content_dlp import ContentDLPEngine, EDMIndex, FingerprintIndex


ROOT = Path(__file__).resolve().parents[1]
OFFICE_TEMPLATES = ROOT / "tests" / "fixtures" / "desktop_dlp_office"
_OFFICE_TEMPLATE_SHA256 = {
    "docx": "9e80afd9ae27452725193821f7058d4a63aff6fdc05ebdb8d4105426a7382028",
    "xlsx": "00498752aa7bd7ec53cb2d05c1bf6a15008396824e51076e6c26254cd72b2078",
    "pptx": "134c4b49da4b735be84beb0b3bfc4257be6d181b582e5080fbfa90d594afcf85",
}
_OFFICE_PART = {"docx": "word/document.xml", "xlsx": "xl/worksheets/sheet1.xml",
                "pptx": "ppt/slides/slide1.xml"}
_OFFICE_PLACEHOLDER = b"SYNTHETIC_DLP_PAYLOAD"
DATASETS = {
    "gretel_en": {
        "id": "gretelai/gretel-pii-masking-en-v1",
        "revision": "e06eb1499ca8d54470f085021cd8e54f9efac7fd",
        "file": "gretel-test.parquet",
        "source_path": "data/test-00000-of-00001.parquet",
        "sha256": "c89a6bffa838edb0f2fc6686bf35da4930944519ac97308b0b6e32298594b5b1",
        "size": 2029143,
    },
    "pii_zh": {
        "id": "wan9yu/pii-bench-zh",
        "revision": "c350b94897af668517ff5de237d89f2ce2eaa6f0",
        "file": "pii-bench-zh.jsonl",
        "source_path": "data/pii_bench_zh.jsonl",
        "sha256": "bcaa54909fd69c6737b8e442c4d740ce1bf5b95b7d4af70b2f2692010e1ff7a5",
        "size": 1834636,
    },
    "pii_zh_chat": {
        "id": "wan9yu/pii-bench-zh",
        "revision": "c350b94897af668517ff5de237d89f2ce2eaa6f0",
        "file": "pii-bench-zh-chat.jsonl",
        "source_path": "data/pii_bench_zh_chat.jsonl",
        "sha256": "4ddacd78dfac49b723032de5e1c29c432a44049245e03a8ea960c86bbf3b765c",
        "size": 853574,
    },
}

_FAKE_SECRET = "Ab3x7Q2m9Pv4Na6Ty8Rz0Ls5Kb1Dc3Fh"
_KNOWN_DOC = ("Project Nebula confidential roadmap phase alpha ships the internal review workflow "
              "phase beta adds the redaction service phase gamma delivers audit controls for all agents.")
_KNOWN_CODE = ("def rotate_signing_key(tenant_id, kms_client):\n"
               "    current = kms_client.get_active_key(tenant_id)\n"
               "    new_key = kms_client.create_key(tenant_id)\n"
               "    return new_key.fingerprint")


def _pdf(text: str) -> bytes:
    writer = PdfWriter()
    page = writer.add_blank_page(width=612, height=792)
    font = DictionaryObject({
        NameObject("/Type"): NameObject("/Font"),
        NameObject("/Subtype"): NameObject("/Type1"),
        NameObject("/BaseFont"): NameObject("/Helvetica"),
    })
    page[NameObject("/Resources")] = DictionaryObject({
        NameObject("/Font"): DictionaryObject({NameObject("/F1"): writer._add_object(font)}),
    })
    content = DecodedStreamObject()
    content.set_data(f"BT /F1 12 Tf 50 700 Td ({text}) Tj ET".encode("ascii"))
    page[NameObject("/Contents")] = writer._add_object(content)
    with BytesIO() as stream:
        writer.write(stream)
        return stream.getvalue()


def _office(extension: str, text: str) -> bytes:
    main = _OFFICE_PART[extension]
    template = (OFFICE_TEMPLATES / f"template.{extension}").read_bytes()
    if hashlib.sha256(template).hexdigest() != _OFFICE_TEMPLATE_SHA256[extension]:
        raise ValueError("Office fixture template digest mismatch")
    replacement = escape(text, quote=False).encode("utf-8")
    with BytesIO() as stream:
        with ZipFile(BytesIO(template)) as source, ZipFile(stream, "w") as archive:
            if main not in source.namelist():
                raise ValueError("Office fixture payload part missing")
            for original in source.infolist():
                contents = source.read(original.filename)
                if original.filename == main:
                    if contents.count(_OFFICE_PLACEHOLDER) != 1:
                        raise ValueError("Office fixture placeholder mismatch")
                    contents = contents.replace(_OFFICE_PLACEHOLDER, replacement)
                entry = ZipInfo(original.filename, date_time=(1980, 1, 1, 0, 0, 0))
                entry.create_system = 0
                entry.external_attr = 0
                archive.writestr(entry, contents, compress_type=original.compress_type)
        return stream.getvalue()


def _fixture_engine(seed: str) -> ContentDLPEngine:
    key = hashlib.sha256(("synthetic-edm-fixture:" + seed).encode()).digest()
    edm = EDMIndex.from_records({"fake-employee-1": {
        "name": "Zhang Wei", "employee_id": "E10293",
    }}, key)
    fingerprint = FingerprintIndex.from_documents({
        "fake-roadmap": ("INTERNAL_DOC", _KNOWN_DOC),
        "fake-source": ("SOURCE_CODE", _KNOWN_CODE),
    })
    return ContentDLPEngine(index=fingerprint, edm_index=edm)


def _fixtures():
    """Yield only synthetic examples with explicit policy expectations."""
    import base64

    secret = "password=" + _FAKE_SECRET
    base64_secret = base64.b64encode(secret.encode()).decode()
    hex_secret = secret.encode().hex()
    text_rows = (
        ("text_public", "ALLOW", "Public conference release notes."),
        ("text_placeholder", "ALLOW", "api_key=${API_KEY}"),
        ("text_masked", "ALLOW", "password=********"),
        ("text_uuid", "ALLOW", "Reference UUID 550e8400-e29b-41d4-a716-446655440000"),
        ("text_secret", "BLOCK", secret),
        ("text_base64", "BLOCK", base64_secret),
        ("text_hex", "BLOCK", hex_secret),
        ("text_entropy", "BLOCK", "deploy token xqeF7P2mZk9Lw3Rt8Vb1Nc6Hy4Jd0Gs5Pa2"),
        ("text_edm", "BLOCK", "Zhang Wei (E10293)"),
        ("text_doc_fragment", "BLOCK", "phase beta adds the redaction service phase gamma delivers audit controls"),
        ("text_code_fragment", "BLOCK", "current = kms_client.get_active_key(tenant_id)\n"
                                    "new_key = kms_client.create_key(tenant_id)"),
        ("text_paraphrase", "BLOCK", "The team will review future steps together."),
    )
    for case_id, expected, text in text_rows:
        yield case_id, "text", expected, "", text
    for extension in ("txt", "pdf", "docx", "xlsx", "pptx"):
        content = "Public conference notes" if extension != "txt" else "Public conference notes."
        bad = secret
        encode = (lambda value: value.encode()) if extension == "txt" else _pdf if extension == "pdf" else (
            lambda value, ext=extension: _office(ext, value))
        yield f"file_{extension}_public", "file", "ALLOW", f"public.{extension}", encode(content)
        yield f"file_{extension}_secret", "file", "BLOCK", f"secret.{extension}", encode(bad)
    yield "file_unsupported", "unsupported", "BLOCK", "attachment.bin", b"synthetic data"
    yield "file_image_only_pdf", "unsupported", "BLOCK", "scan.pdf", _empty_pdf()


def _empty_pdf() -> bytes:
    writer = PdfWriter()
    writer.add_blank_page(width=612, height=792)
    with BytesIO() as stream:
        writer.write(stream)
        return stream.getvalue()


def evaluate_fixtures(seed: str) -> dict:
    engine = _fixture_engine(seed)
    matrix = defaultdict(Counter)
    rows = []
    latency = []
    for case_id, kind, expected, name, payload in _fixtures():
        started = time.perf_counter()
        verdict = engine.inspect_text(payload) if kind == "text" else engine.inspect_file_bytes(name, payload)
        elapsed = (time.perf_counter() - started) * 1000
        latency.append(elapsed)
        if kind != "unsupported":
            matrix[expected][verdict.decision] += 1
        rows.append({
            "case": case_id, "kind": kind, "expected": expected, "actual": verdict.decision,
            "policy_would_deny": verdict.decision != "ALLOW", "reason": verdict.reason,
            "rule_ids": verdict.rule_ids, "payload_sha256": hashlib.sha256(
                payload.encode() if isinstance(payload, str) else payload).hexdigest(),
            "elapsed_ms": round(elapsed, 3),
        })
    return {
        "matrix": {key: dict(matrix[key]) for key in ("BLOCK", "ALLOW")},
        "rows": rows,
        "latency_ms": {"p50": _percentile(latency, .5), "p95": _percentile(latency, .95),
                       "p99": _percentile(latency, .99)},
        "known_miss": "text_paraphrase",
        "note": "A future desktop gate must deny REVIEW; this offline evaluation does not verify live enforcement. Unsupported formats are counted separately from detection.",
    }


def _local_file(directory: Path, descriptor: dict) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / descriptor["file"]
    if not path.exists():
        url = (f'https://huggingface.co/datasets/{descriptor["id"]}/resolve/'
               f'{descriptor["revision"]}/{descriptor["source_path"]}')
        temporary = path.with_suffix(path.suffix + ".part")
        with urlopen(url, timeout=60) as response, temporary.open("wb") as output:
            size = 0
            while chunk := response.read(1024 * 1024):
                size += len(chunk)
                if size > descriptor["size"]:
                    raise ValueError(f"dataset size exceeds pinned value: {descriptor['id']}")
                output.write(chunk)
        if (size != descriptor["size"]
                or hashlib.sha256(temporary.read_bytes()).hexdigest() != descriptor["sha256"]):
            raise ValueError(f"downloaded dataset digest or size mismatch: {descriptor['id']}")
        temporary.replace(path)
    if path.stat().st_size != descriptor["size"]:
        raise ValueError(f"dataset size mismatch: {descriptor['id']}")
    with path.open("rb") as stream:
        if hashlib.file_digest(stream, "sha256").hexdigest() != descriptor["sha256"]:
            raise ValueError(f"dataset digest mismatch: {descriptor['id']}")
    return path


def _gretel_entities(entities: str) -> list[dict]:
    if not isinstance(entities, str) or len(entities) > 100_000:
        raise ValueError("unexpected Gretel entity annotation size")
    if not entities.strip():
        return []
    # The publisher's Parquet stores a Python list representation, not JSON.
    try:
        parsed = json.loads(entities)
    except json.JSONDecodeError:
        parsed = ast.literal_eval(entities)
    if not isinstance(parsed, list) or any(not isinstance(item, dict) for item in parsed):
        raise ValueError("unexpected Gretel entity annotation")
    return parsed


def _gretel_labels(entities: str) -> set[str]:
    return {str(kind).lower() for entity in _gretel_entities(entities) for kind in entity.get("types", [])}


def _redact_entities(text: str, values) -> str:
    redacted = text
    for value in sorted({value for value in values if isinstance(value, str) and len(value) >= 2},
                        key=len, reverse=True):
        redacted = redacted.replace(value, "REDACTED")
    return redacted


def _rows(paths: dict[str, Path]):
    try:
        import duckdb
    except ImportError as error:
        raise RuntimeError("Run with --with duckdb==2.0.0 for the pinned Parquet corpus") from error
    db = duckdb.connect()
    for uid, text, entities in db.execute(
            "SELECT uid, text, entities FROM read_parquet(?)", [str(paths["gretel_en"])]).fetchall():
        annotations = _gretel_entities(entities)
        yield "gretel_en", str(uid), text, {
            str(kind).lower() for entity in annotations for kind in entity.get("types", [])
        }, _redact_entities(text, (entity.get("entity") for entity in annotations))
    for source in ("pii_zh", "pii_zh_chat"):
        with paths[source].open(encoding="utf-8") as stream:
            for line in stream:
                row = json.loads(line)
                yield source, str(row["id"]), row["text"], {
                    str(entity.get("type", "")).lower() for entity in row.get("entities", [])
                }, _redact_entities(row["text"], (entity.get("text") for entity in row.get("entities", [])))


def _select(rows, per_dataset: int, seed: str):
    if per_dataset < 0:
        raise ValueError("per_dataset must be nonnegative")
    by_source = defaultdict(list)
    for row in rows:
        by_source[row[0]].append(row)
    for source, group in by_source.items():
        if len({row[1] for row in group}) != len(group):
            raise ValueError(f"duplicate dataset row ID: {source}")
        ranked = sorted(group, key=lambda row: hashlib.sha256(
            f"{seed}:{source}:{row[1]}".encode()).digest())
        yield from ranked if per_dataset == 0 else ranked[:per_dataset]


def _percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    return round(ordered[min(len(ordered) - 1, int((len(ordered) - 1) * fraction))], 3)


def evaluate(paths: dict[str, Path], *, per_dataset: int = 0, seed: str = "2026-11-04") -> dict:
    engine = ContentDLPEngine()
    counts = defaultdict(Counter)
    redacted_counts = defaultdict(Counter)
    label_counts = defaultdict(lambda: defaultdict(Counter))
    timings = defaultdict(list)
    for source, _, body, labels, redacted in _select(_rows(paths), per_dataset, seed):
        start = time.perf_counter()
        verdict = engine.inspect_text(body)
        timings[source].append((time.perf_counter() - start) * 1000)
        counts[source][verdict.decision] += 1
        counts[source]["rows"] += 1
        redacted_counts[source][engine.inspect_text(redacted).decision] += 1
        for label in labels:
            label_counts[source][label][verdict.decision] += 1
    return {
        "schema": "transpect.desktop-dlp.dataset-evaluation/1.1",
        "seed": seed, "sample_per_dataset": per_dataset,
        "selection_mode": "full" if per_dataset == 0 else "hash_ranked_sample",
        "blind_holdout": False, "policy_truth_available_for_public_corpora": False,
        "live_enforcement_verified": False,
        "interpretation": ("These corpora contain annotated PII, including weak entities such as names. "
                           "ALLOW is not automatically a policy error; per-label rates are diagnostic. "
                           "Redacted counterparts remove annotated values and provide only an approximate "
                           "false-positive diagnostic because unannotated sensitive content may remain. "
                           "These corpora were used during development, so this is not a blind holdout. "
                           "A future desktop gate must deny REVIEW; live enforcement is not verified here. "
                           "The confusion matrix below uses separate developer-made synthetic fixtures "
                           "with explicit policy labels."),
        "datasets": {name: {"id": descriptor["id"], "revision": descriptor["revision"],
                            "sha256": descriptor["sha256"],
                            "decisions": dict(counts[name]),
                            "redacted_proxy_decisions": dict(redacted_counts[name]),
                            "by_entity_label": {label: dict(counter) for label, counter in sorted(label_counts[name].items())},
                            "latency_ms": {"p50": _percentile(timings[name], .5),
                                           "p95": _percentile(timings[name], .95),
                                           "p99": _percentile(timings[name], .99)}}
                     for name, descriptor in DATASETS.items()},
        "fixtures": evaluate_fixtures(seed),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", type=Path, default=ROOT / "runs/desktop-dlp-datasets")
    parser.add_argument("--output", type=Path, default=ROOT / "runs/desktop-dlp-datasets/report.json")
    parser.add_argument("--per-dataset", type=int, default=0,
                        help="0 evaluates every row (default); use 500 for a fixed quick sample each")
    parser.add_argument("--seed", default="2026-11-04")
    args = parser.parse_args()
    if args.per_dataset < 0:
        parser.error("per-dataset must be nonnegative")
    paths = {name: _local_file(args.directory, descriptor) for name, descriptor in DATASETS.items()}
    result = evaluate(paths, per_dataset=args.per_dataset, seed=args.seed)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    for name, row in result["datasets"].items():
        print(name, row["decisions"], "redacted_proxy", row["redacted_proxy_decisions"], row["latency_ms"])
    print("synthetic_fixture_matrix", result["fixtures"]["matrix"])
    print("known_miss", result["fixtures"]["known_miss"])
    print(args.output)


if __name__ == "__main__":
    main()
