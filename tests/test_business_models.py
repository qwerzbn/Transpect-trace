import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from transpect_trace.flow.scenarios.models import (
    BusinessScenarioReport, ScenarioEvidence, ScenarioOutbound, ScenarioProcess, ScenarioRelation,
)


def test_process_membership_is_independent_of_parent_lineage():
    row = ScenarioProcess(role='exporter', pid=10, creation_filetime=20, image_sha256='a' * 64)
    assert row.key == (10, 20) and row.parent_pid is None
    assert row.membership_basis == 'explicit_registration'
    with pytest.raises(ValidationError):
        ScenarioProcess(**{**row.model_dump(), 'membership_basis': 'observed_lineage'})
    with pytest.raises(ValidationError):
        ScenarioProcess(**{**row.model_dump(), 'parent_pid': 1})


@pytest.mark.parametrize('field', ['body', 'prompt', 'authorization', 'cookie', 'command_line', 'url'])
def test_audit_models_have_no_raw_body_or_secret_fields(field):
    with pytest.raises(ValidationError):
        ScenarioEvidence(evidence_id='e', stage_id='upload', provenance='ecapture',
                         **{field: 'DO_NOT_LOG_TEST_SECRET'})


def test_all_new_records_are_observe_only_and_cannot_claim_taint():
    with pytest.raises(ValidationError):
        BusinessScenarioReport(session_id='s', scenario='git', case='public', can_enforce=True)
    with pytest.raises(ValidationError):
        ScenarioRelation(relation_id='r', left_id='a', right_id='b', method='content_candidate',
                         byte_level_taint_proof=True)


def test_tls_and_request_layers_cannot_be_interchanged():
    with pytest.raises(ValidationError):
        ScenarioOutbound(attempt_id='attempt', capture_source='native_request', capture_layer='tls',
                         completeness='complete')


def test_partial_content_cannot_assert_no_match():
    with pytest.raises(ValidationError):
        ScenarioOutbound(attempt_id='attempt', capture_source='ecapture', capture_layer='tls',
                         completeness='partial', detection_status='no_match')


def test_hash_must_have_a_length_and_matched_needs_finding():
    with pytest.raises(ValidationError):
        ScenarioEvidence(evidence_id='e', stage_id='upload', provenance='ecapture', body_sha256='a' * 64)
    with pytest.raises(ValidationError):
        ScenarioOutbound(attempt_id='attempt', capture_source='ecapture', capture_layer='tls',
                         completeness='complete', detection_status='matched')


def test_generated_business_schemas_match_public_models():
    from transpect_trace.flow.scenarios.manifest import BusinessScenarioManifest
    root = Path(__file__).resolve().parents[1] / 'schemas'
    for name, model in [('business-scenario-manifest-v1.schema.json', BusinessScenarioManifest),
                        ('business-scenario-report-v1.schema.json', BusinessScenarioReport)]:
        assert json.loads((root / name).read_text(encoding='utf-8')) == model.model_json_schema(mode='serialization')
