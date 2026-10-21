"""Business fixtures for actual required refusals and benign controls."""
import json
from pathlib import Path

import pytest

from transpect_trace.guard.policy import GuardPolicy, GuardRequest, PolicyEngine


def evaluate(output,policy=None):
    return PolicyEngine(policy or GuardPolicy()).evaluate(GuardRequest(
        schema='transpect.guard.request/1.0',request_id='fixture-1',guard_session_id='fixture',pid=1,tid=1,
        kind='model.request',protocol='http',completeness='complete',payload_utf8=json.dumps({
            'model':'gpt-probe','input':[{'type':'function_call_output','call_id':'call-fixture','output':output}]})))


@pytest.mark.parametrize('output',['ERROR mysql_password=FAKE_ONLY_0123456789abcdef',
                                   'api_secret=FAKE_ONLY_0123456789abcdef'])
def test_flat_credential_in_realistic_tool_output_is_rejected(output):
    decision,audit=evaluate(output)
    assert decision.decision=='deny' and 'CONFIG_CREDENTIAL' in audit['matched_rule_ids']


def test_clean_diagnostic_output_remains_allowed():
    decision,_=evaluate('INFO synthetic test completed; request_id=fixture-123')
    assert decision.decision=='allow'


@pytest.mark.parametrize('text',[
    '# Synthetic proprietary function\ndef calculate(value):\n    return value * 0.731\n',
    '企业内部合成测试文档，不包含真实企业信息。\n这一段用于验证登记内容的精确匹配保护功能。\n'])
def test_registered_exact_tool_text_is_rejected(tmp_path,text):
    source=tmp_path/'fixture.txt';source.write_text(text,encoding='utf-8')
    decision,audit=evaluate(text,GuardPolicy(registered_files=[source]))
    assert decision.decision=='deny' and 'REGISTERED_CONTENT' in audit['matched_rule_ids']


@pytest.mark.parametrize('output',[
    'Authorization: Bearer FAKE_ONLY_0123456789abcdef',
    'SYNTHETIC customer phone=13800000000 email=fixture@example.invalid',
    'database_url=postgresql://fixture:FAKE_ONLY_0123456789abcdef@127.0.0.1:5432/fixture',
    json.dumps({'api_secret':'FAKE_ONLY_0123456789abcdef'}),
])
def test_sensitive_business_tool_output_requires_refusal(output):
    decision,_=evaluate(output,GuardPolicy(pii_rules=True))
    assert decision.decision=='deny'


def test_registered_content_survives_windows_newline_transform(tmp_path):
    text='# Synthetic proprietary function\ndef calculate(value):\n    return value * 0.731\n'
    source=tmp_path/'fixture.txt';source.write_text(text,encoding='utf-8')
    decision,_=evaluate(text.replace('\n','\r\n'),GuardPolicy(registered_files=[source]))
    assert decision.decision=='deny'


def test_experiment_valid_does_not_mean_sensitive_content_was_protected(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1]/'scripts'))
    from probe_codex_business_content import assess
    raw=dict(native_ready=True,disk_unchanged=True,fixture_cleanup_terminated_child=False,
             blocked_sensitive_body_zero_at_oracle=False,native_error_displayed=False,
             origin_connections=[dict(marker_in_origin_payload=True)],returncode=0,policy_events=[])
    observations=[dict(marker_in_tool_result=True,decision='allow')]
    result=assess(raw,observations,'registered_source','http',[],'0'*64)
    assert result['experiment_valid'] and result['protection_status']=='coverage_gap'
    assert not result['actual_blocked'] and not result['expected_outcome_met']
    assert not assess(raw,[],'registered_source','http',[],'0'*64)['experiment_valid']
