"""Content-recognition DLP engine: each layer catches its class, fusion decides, encoding
dodges are canonicalized, and a pure semantic paraphrase is an honest declared miss."""
import base64
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import demo_content_dlp as dlp  # noqa: E402


def test_each_layer_catches_its_class():
    engine = dlp.ContentDLPEngine()
    # (1) rules + context: an AWS key id.
    assert engine.inspect("key AKIAABCDEFGHIJKLMNOP").action in ("BLOCK", "REVIEW")
    # (2) entropy: an unknown-format high-entropy token with no assignment syntax.
    assert "SECRET" in engine.inspect(f"token {dlp._NOVEL_SECRET}").category_scores
    # (3) EDM with corroboration: name + SSN of one record -> high confidence BLOCK.
    edm = engine.inspect("Zhang Wei ssn 123-45-6789")
    assert edm.action == "BLOCK" and "PII" in edm.category_scores
    # (4) fingerprint: a partial copy of a known internal doc.
    frag = "phase gamma delivers the information flow control plane for all internal agents"
    assert engine.inspect(frag).action in ("BLOCK", "REVIEW")


def test_edm_single_field_is_weak_evidence():
    engine = dlp.ContentDLPEngine()
    # A lone common first name must not block on its own (corroboration matters).
    assert engine.inspect("Hi Li, see the public blog post.").action == "ALLOW"


def test_encoding_dodge_is_canonicalized_but_paraphrase_is_an_honest_miss():
    matrix = dlp.evasion_matrix()
    by = {r["case"]: r for r in matrix["rows"]}
    assert by["base64_encoded_secret"]["caught"] is True
    assert by["novel_format_secret"]["caught"] is True
    assert by["known_doc_fragment"]["caught"] is True
    # Pure semantic rewrite is NOT caught by layers (1)-(4) -- reported, not hidden.
    assert by["paraphrased_internal_doc"]["caught"] is False
    assert matrix["matrix_as_expected"] is True


def test_masked_and_placeholder_values_are_not_false_positives():
    engine = dlp.ContentDLPEngine()
    assert engine.inspect("password=********").action == "ALLOW"
    assert engine.inspect("api_key=${API_KEY}").action == "ALLOW"


def test_inspector_error_fails_closed():
    engine = dlp.ContentDLPEngine()
    boom = lambda text: (_ for _ in ()).throw(RuntimeError("inspector crashed"))
    engine.LAYERS = (boom,)
    report = engine.inspect("anything")
    assert report.action == "BLOCK" and "INSPECTION_ERROR" in report.category_scores


def test_uploaded_file_with_code_and_secret_is_blocked():
    demo = dlp.file_upload_demo()
    assert demo["action"] == "BLOCK"
    assert "rules+context" in demo["layers_fired"]
