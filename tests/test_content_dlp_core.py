"""Bounded, local content recognition used by the desktop send gate."""
from __future__ import annotations

import base64
from io import BytesIO
from zipfile import ZIP_DEFLATED, ZipFile

from pypdf import PdfWriter
from pypdf.generic import DecodedStreamObject, DictionaryObject, NameObject

from transpect_trace.protect.content_dlp import ContentDLPEngine, EDMIndex, FingerprintIndex


SECRET = "Ab3x7Q2m9Pv4Na6Ty8Rz0Ls5Kb1Dc3Fh"


def _index() -> FingerprintIndex:
    return FingerprintIndex.from_documents({
        "roadmap": ("INTERNAL_DOC", "Project Nebula confidential roadmap phase alpha ships the internal review workflow "
                    "phase beta adds the redaction service phase gamma delivers audit controls for all agents."),
        "signing": ("SOURCE_CODE", "def rotate_signing_key(tenant_id, kms_client):\n"
                    "    current = kms_client.get_active_key(tenant_id)\n"
                    "    new_key = kms_client.create_key(tenant_id)\n"
                    "    return new_key.fingerprint"),
    })


def _office(extension: str, text: str, *, extra: tuple[str, bytes] | None = None) -> bytes:
    root = {"docx": "word/document.xml", "xlsx": "xl/workbook.xml", "pptx": "ppt/presentation.xml"}[extension]
    with BytesIO() as stream:
        with ZipFile(stream, "w", ZIP_DEFLATED) as archive:
            archive.writestr("[Content_Types].xml", '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>')
            archive.writestr(root, f"<root><t>{text}</t></root>")
            if extra:
                archive.writestr(*extra)
        return stream.getvalue()


def _pdf(text: str | None) -> bytes:
    writer = PdfWriter()
    page = writer.add_blank_page(width=612, height=792)
    if text:
        font = DictionaryObject({
            NameObject("/Type"): NameObject("/Font"),
            NameObject("/Subtype"): NameObject("/Type1"),
            NameObject("/BaseFont"): NameObject("/Helvetica"),
        })
        font_ref = writer._add_object(font)
        page[NameObject("/Resources")] = DictionaryObject({
            NameObject("/Font"): DictionaryObject({NameObject("/F1"): font_ref}),
        })
        content = DecodedStreamObject()
        content.set_data(f"BT /F1 12 Tf 50 700 Td ({text}) Tj ET".encode("ascii"))
        page[NameObject("/Contents")] = writer._add_object(content)
    with BytesIO() as stream:
        writer.write(stream)
        return stream.getvalue()


def test_four_layers_and_no_plaintext_in_verdict():
    edm = EDMIndex.from_records({"employee-1": {"name": "Zhang Wei", "employee_id": "E10293"}}, b"k" * 32)
    engine = ContentDLPEngine(index=_index(), edm_index=edm)
    assert engine.inspect_text("aws_access_key_id=AKIAABCDEFGHIJKLMNOP").decision == "BLOCK"
    assert engine.inspect_text("deploy token xqeF7P2mZk9Lw3Rt8Vb1Nc6Hy4Jd0Gs5Pa2").decision == "BLOCK"
    assert engine.inspect_text("Zhang Wei (E10293)").decision == "BLOCK"
    assert engine.inspect_text("phase beta adds the redaction service phase gamma delivers audit controls").decision == "BLOCK"
    assert engine.inspect_text("current = kms_client.get_active_key(tenant_id)\n"
                               "new_key = kms_client.create_key(tenant_id)").decision != "ALLOW"
    verdict = engine.inspect_text("password=" + SECRET)
    assert verdict.decision == "BLOCK" and SECRET not in repr(verdict)
    assert SECRET not in repr(edm)
    assert engine.inspect_text("Zhang Wei").decision == "ALLOW"


def test_encoded_secret_validators_and_hard_negatives():
    engine = ContentDLPEngine()
    encoded = base64.b64encode(("password=" + SECRET).encode()).decode()
    assert engine.inspect_text(encoded).decision == "BLOCK"
    assert engine.inspect_text("credit card 4111 1111 1111 1111").decision == "BLOCK"
    assert engine.inspect_text("联系人手机18863794026").decision == "REVIEW"
    assert engine.inspect_text("旅客护照号G10122691").decision == "BLOCK"
    assert engine.inspect_text("银行卡号6225684192832768").decision != "ALLOW"
    assert engine.inspect_text("reference 6225684192832768").decision == "ALLOW"
    assert engine.inspect_text("password=******** and api_key=${API_KEY}").decision == "ALLOW"
    assert engine.inspect_text("public UUID 550e8400-e29b-41d4-a716-446655440000").decision == "ALLOW"
    # Syntax-only fingerprints do not catch a semantic rewrite of a registered document.
    assert ContentDLPEngine(index=_index()).inspect_text("The team will review future steps together.").decision == "ALLOW"


def test_text_pdf_and_office_file_bytes():
    engine = ContentDLPEngine()
    assert engine.inspect_file_bytes("good.txt", b"Public release notes for the conference.").decision == "ALLOW"
    assert engine.inspect_file_bytes("bad.py", ("password=" + SECRET).encode()).decision == "BLOCK"
    assert engine.inspect_file_bytes("bad.pdf", _pdf("password=" + SECRET)).decision == "BLOCK"
    assert engine.inspect_file_bytes("good.pdf", _pdf("Public conference notes")).decision == "ALLOW"
    for ext in ("docx", "xlsx", "pptx"):
        assert engine.inspect_file_bytes("bad." + ext, _office(ext, "password=" + SECRET)).decision == "BLOCK"
        assert engine.inspect_file_bytes("good." + ext, _office(ext, "Public conference notes")).decision == "ALLOW"


def test_uninspectable_files_fail_closed():
    engine = ContentDLPEngine()
    samples = (
        ("legacy.doc", b"old file"),
        ("scanned.pdf", _pdf(None)),
        ("broken.pdf", b"not a pdf"),
        ("binary.txt", b"\xff\x00"),
        ("unknown.bin", b"just bytes"),
        ("bomb.docx", _office("docx", "safe", extra=("word/media/image1.png", b"\x89PNG"))),
        ("trailing.docx", _office("docx", "safe") + b"hidden bytes"),
        ("external.docx", _office("docx", "safe", extra=(
            "word/_rels/document.xml.rels",
            b'<Relationships><Relationship TargetMode="External" Target="https://example.invalid"/></Relationships>'))),
        ("too_large.txt", b"a" * (16 * 1024 * 1024 + 1)),
    )
    for filename, data in samples:
        result = engine.inspect_file_bytes(filename, data)
        assert result.decision == "BLOCK" and result.reason == "FILE_UNINSPECTABLE", filename


def test_inspector_error_fails_closed(monkeypatch):
    from transpect_trace.protect import content_dlp

    def crash(*_args):
        raise RuntimeError("fake secret in error message")

    monkeypatch.setattr(content_dlp, "_rules", crash)
    result = ContentDLPEngine().inspect_text("public text")
    assert result.decision == "BLOCK" and result.reason == "INSPECTION_FAILED"
    assert "fake secret" not in repr(result)


def test_email_rule_is_bounded_on_long_username_like_text():
    engine = ContentDLPEngine()
    # The old unanchored local-part regex retried from every character, spent
    # seconds on this ordinary text, and returned INSPECTION_FAILED.
    long_text = "a." * 15_000
    verdict = engine.inspect_text(long_text)
    assert verdict.decision == "ALLOW" and verdict.reason == "REQUIRED_CHECKS_COMPLETE"
    found = engine.inspect_text("contact name@example.com for public notes")
    assert "EMAIL" in found.rule_ids


def test_office_split_runs_and_metadata_are_checked():
    engine = ContentDLPEngine()
    split = _office("docx", "pass</t><t>word=" + SECRET)
    assert engine.inspect_file_bytes("split.docx", split).decision == "BLOCK"
    metadata = _office("docx", "Public content", extra=(
        "word/comments.xml", ("<root title=\"password=" + SECRET + "\"/>").encode()))
    assert engine.inspect_file_bytes("metadata.docx", metadata).decision == "BLOCK"


def test_office_structural_attributes_do_not_become_content_tokens():
    engine = ContentDLPEngine()
    structural = _office("xlsx", "Public notes", extra=(
        "xl/styles.xml",
        b'<root><style id="50000" count="300000" size="35000" '
        b'guid="5C22544A-7EE6-4342-B048-85BDC9FD1C3A"/></root>',
    ))
    assert engine.inspect_file_bytes("public.xlsx", structural).decision == "ALLOW"


def test_edm_requires_fields_from_the_same_record():
    index = EDMIndex.from_records({
        "a": {"name": "Alice Example", "employee_id": "E10293"},
        "b": {"name": "Bob Example", "employee_id": "E20481"},
    }, b"k" * 32)
    engine = ContentDLPEngine(edm_index=index)
    assert engine.inspect_text("Alice Example E20481").decision == "ALLOW"
    assert engine.inspect_text("Alice Example E10293").decision == "BLOCK"
