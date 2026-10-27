import hashlib

import pytest

from transpect_trace.protect.content_analysis import (
    ContentAnalysisEngine,
    ContentAnalysisPolicy,
    ContentAnalysisRequest,
)
from transpect_trace.protect.content_analysis.models import MAX_CONTENT_BYTES
from transpect_trace.protect.detection import ContentIndex


TOKEN = "sdk-request-token-that-must-not-be-audited"
ACTION = "sdk-user-action-that-must-not-be-audited"


def request(body=b"ordinary fixture text", **kwargs):
    values = dict(
        request_token=TOKEN,
        connector="FILE_ATTACHED",
        reason="FILE_PICKER_DIALOG",
        destination_url="https://chatgpt.com/?token=must-not-be-audited",
        body=body,
        user_action_id=ACTION,
        tags=["dlp"],
    )
    values.update(kwargs)
    return ContentAnalysisRequest.from_sdk(**values)


def test_clean_file_and_paste_are_allowed_after_required_checks():
    engine = ContentAnalysisEngine(ContentAnalysisPolicy(allowed_hosts=["chatgpt.com"]))
    file_verdict, _ = engine.evaluate(request())
    paste_verdict, _ = engine.evaluate(
        request(
            "普通中文粘贴内容".encode(),
            connector="BULK_DATA_ENTRY",
            reason="CLIPBOARD_PASTE",
        )
    )
    assert file_verdict.decision == paste_verdict.decision == "ALLOW"
    assert file_verdict.action == paste_verdict.action == "allow"


@pytest.mark.parametrize(
    "connector,reason",
    [
        ("FILE_ATTACHED", "FILE_PICKER_DIALOG"),
        ("FILE_ATTACHED", "DRAG_AND_DROP"),
        ("BULK_DATA_ENTRY", "CLIPBOARD_PASTE"),
        ("BULK_DATA_ENTRY", "DRAG_AND_DROP"),
    ],
)
def test_credentials_block_for_supported_file_and_text_reasons(connector, reason):
    verdict, audit = ContentAnalysisEngine().evaluate(
        request(b"password=FakeSecret12345", connector=connector, reason=reason)
    )
    assert verdict.decision == "BLOCK" and verdict.action == "block"
    assert audit.decision == "BLOCK"
    assert "CONFIG_CREDENTIAL" in audit.rule_ids


def test_registered_content_blocks_without_serializing_registered_text():
    secret = "fake-company-source-fragment-" * 4
    index = ContentIndex.register(
        "fixture/1", [("fixture", secret, "CONFIDENTIAL", ["source_code"])], chunk_size=32
    )
    verdict, audit = ContentAnalysisEngine(index=index).evaluate(
        request(("prefix" + secret + "suffix").encode())
    )
    assert verdict.decision == "BLOCK"
    assert audit.registration_ids == ["fixture"]
    assert secret not in verdict.model_dump_json()
    assert secret not in audit.model_dump_json()


def test_request_and_audit_are_privacy_safe():
    secret = b"password=UniqueFakeSecret12345"
    req = request(secret)
    verdict, audit = ContentAnalysisEngine().evaluate(req)
    combined = req.model_dump_json() + verdict.model_dump_json() + audit.model_dump_json()
    for forbidden in (
        secret.decode(),
        TOKEN,
        ACTION,
        "must-not-be-audited",
        "https://chatgpt.com/",
    ):
        assert forbidden not in combined
    assert audit.destination_host == "chatgpt.com"
    assert audit.body_sha256 == hashlib.sha256(secret).hexdigest()
    with pytest.raises(ValueError):
        request(limitations=["path=C:/sensitive/file.txt"])
    with pytest.raises(ValueError):
        ContentAnalysisPolicy(allowed_hosts=["https://chatgpt.com/?token=secret"])


@pytest.mark.parametrize(
    "changes,reason",
    [
        ({"completeness": "partial"}, "INCOMPLETE_CONTENT"),
        ({"encoding_state": "binary"}, "UNSUPPORTED_CONTENT_ENCODING"),
        ({"limitations": ["capture_gap"]}, "INCOMPLETE_CONTENT"),
        ({"expires_at": 99}, "DECISION_DEADLINE_EXPIRED"),
    ],
)
def test_uninspectable_content_fails_closed(changes, reason):
    verdict, _ = ContentAnalysisEngine().evaluate(request(**changes), now=100)
    assert verdict.decision == "UNKNOWN"
    assert verdict.action == "block"
    assert verdict.reason == reason


def test_unsupported_reason_and_unknown_destination_fail_closed():
    verdict, _ = ContentAnalysisEngine().evaluate(request(reason="UNKNOWN"))
    assert verdict.reason == "UNSUPPORTED_CONNECTOR_REASON" and verdict.action == "block"
    verdict, _ = ContentAnalysisEngine(
        ContentAnalysisPolicy(allowed_hosts=["allowed.example"])
    ).evaluate(request())
    assert verdict.reason == "DESTINATION_NOT_ALLOWED_OR_UNKNOWN"


def test_metadata_only_round_trip_cannot_authorize_content():
    original = request()
    restored = ContentAnalysisRequest.model_validate_json(original.model_dump_json())
    verdict, _ = ContentAnalysisEngine().evaluate(restored)
    assert verdict.decision == "UNKNOWN"
    assert verdict.reason == "CONTENT_SNAPSHOT_UNAVAILABLE"


def test_utf8_bom_crlf_and_one_mebibyte_boundary_are_supported():
    body = b"\xef\xbb\xbf" + ("普通内容\r\n".encode() * 4)
    assert ContentAnalysisEngine().evaluate(request(body))[0].decision == "ALLOW"
    boundary = b"a" * MAX_CONTENT_BYTES
    assert ContentAnalysisEngine().evaluate(request(boundary))[0].decision == "ALLOW"
    with pytest.raises(ValueError):
        request(boundary + b"x")


def test_snapshot_and_token_hash_mismatch_are_rejected():
    req = request()
    req.body = b"changed"
    with pytest.raises(ValueError):
        ContentAnalysisRequest.model_validate(req.model_dump() | {"body": req.body})
    with pytest.raises(ValueError):
        ContentAnalysisRequest.model_validate(
            request().model_dump() | {"request_token": "wrong"}
        )
