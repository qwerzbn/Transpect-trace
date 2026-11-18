"""Paired benign/secret regressions for canonical decoding and evidence fusion."""
from pathlib import Path
import base64
import runpy
import time

import pytest

from transpect_trace.protect.content_dlp import ContentDLPEngine, fuse


def test_synthetic_paired_matrix():
    script = Path(__file__).resolve().parents[1] / "scripts/evaluate_content_regressions.py"
    report = runpy.run_path(str(script))["evaluate"]()
    assert report["passed"], [row for row in report["cases"] if not row["passed"]]


def test_decoding_does_not_manufacture_independent_evidence():
    assert fuse((("PII", "EMAIL", .35), ("PII", "EMAIL_DECODED", .45))) == {"PII": .45}
    assert fuse((("SECRET", "ENTROPY_TOKEN", .6), ("SECRET", "ENTROPY_TOKEN_DECODED", .6))) == {"SECRET": .6}


def test_maximum_rule_evidence_is_not_overwritten_by_a_later_weak_hit():
    verdict = ContentDLPEngine().inspect_text("email alice@example.test\n" + " " * 100 + "bob@example.test")
    assert next(score for _, rule, score in verdict.evidence if rule == "EMAIL") == .55


def test_split_sequence_requires_explicit_concatenation():
    prefix = "parts = ['ghp_a1B2c3D4e5F6g7H8iJ9J0', 'k1L2m3N4o5P6q7R8']\n"
    assert "GITHUB_TOKEN_SPLIT" in ContentDLPEngine().inspect_text(prefix + "token = parts[0] + parts[1]").rule_ids
    assert "GITHUB_TOKEN_SPLIT" not in ContentDLPEngine().inspect_text(prefix + "token = parts[0]").rule_ids


def test_small_escape_in_large_benign_text_does_not_consume_plaintext_as_decoding_budget():
    text = "release notes " * 80000 + "%20"
    verdict = ContentDLPEngine().inspect_text(text)
    assert verdict.decision == "ALLOW", verdict


@pytest.mark.parametrize(('value', 'expected_rule'), [
    ('sk-proj-' + 'aB3d4E' * 6, 'OPENAI_API_KEY'),
    ('-----BEGIN OPENSSH PRIVATE KEY-----', 'PRIVATE_KEY'),
    ('Bearer ' + 'a1B2c3D4e5F6g7H8iJ9J0k1L2m3N4o5P6q7R8', 'BEARER_TOKEN'),
    ('4 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1', 'PAYMENT_CARD_CONTEXT_UNVERIFIED'),
    ('姓名：张三', 'CN_NAME'),
])
def test_long_view_prefilter_preserves_cross_boundary_matches(monkeypatch, value, expected_rule):
    from transpect_trace.protect import content_dlp as dlp

    # Credential witness starts five characters before the cut. The payment
    # case has fewer than six digits on one side and uses a grouped value.
    prefix = 'test note ' * (dlp._WITNESS_BLOCK // 10)
    prefix = prefix[:dlp._WITNESS_BLOCK - 15].ljust(dlp._WITNESS_BLOCK - 5)
    text = prefix + value + ' bank card'
    actual = dlp._rules([(text, False)], time.monotonic() + 10)
    monkeypatch.setattr(dlp, '_WITNESS_BLOCK', len(text) + 1)
    reference = dlp._rules([(text, False)], time.monotonic() + 10)
    assert any(row.rule_id == expected_rule for row in reference)
    assert actual == reference


def test_large_nested_view_still_detects_token_and_reuses_unchanged_blocks(monkeypatch):
    from transpect_trace.protect import content_dlp as dlp

    original = dlp._block_witnesses
    inspected = []

    def count(block):
        inspected.append(block)
        return original(block)

    monkeypatch.setattr(dlp, '_block_witnesses', count)
    text = 'public release. ' * 14000 + 'g%2568p_' + 'z7F5rTx9' * 5
    verdict = dlp.ContentDLPEngine().inspect_text(text)
    assert 'GITHUB_TOKEN_DECODED' in verdict.rule_ids
    # The same first block is shared by three distinct complete views.
    assert inspected.count(text[:dlp._WITNESS_BLOCK + dlp._WITNESS_OVERLAP]) == 1


def test_encoded_run_straddling_scan_windows_is_fully_decoded():
    from transpect_trace.protect import content_dlp as dlp

    # The short record has exactly 16 encoded characters, eight on each side.
    candidate = base64.b64encode(b'ghp_' + b'a1B2c3' * 6).decode()
    encoded_phone = base64.b64encode(b'x13800138000').decode()
    for token, expected in ((candidate, 'GITHUB_TOKEN_DECODED'), (encoded_phone, 'CN_PHONE_DECODED')):
        text = ' ' * (dlp._WITNESS_BLOCK - 8) + token
        verdict = dlp.ContentDLPEngine().inspect_text(text)
        assert expected in verdict.rule_ids


@pytest.mark.parametrize(('text', 'expected_rule'), [
    ('Normal release notes. ' * 3200 + '\ngithub_pat_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8',
     'GITHUB_TOKEN'),
    ('const a = "github_pat_a1B2c3D4e5F6g7H8"; const b = "i9J0k1L2m3N4o5P6"; console.log(a + b);',
     'GITHUB_TOKEN_SPLIT'),
    ('parts = ["github_pat_a1B2c3D4e5F6g7H8", "i9J0k1L2m3N4o5P6"]; send(parts[0] + parts[1]);',
     'GITHUB_TOKEN_SPLIT'),
], ids=['long-pat', 'split-constants-pat', 'split-array-pat'])
def test_fine_grained_github_tokens_survive_literal_prefilters(text, expected_rule):
    assert 'gh' not in text  # github_pat_ is a separate required prefix branch.
    verdict = ContentDLPEngine().inspect_text(text)
    assert verdict.decision == 'BLOCK'
    assert expected_rule in verdict.rule_ids
