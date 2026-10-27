import hashlib
import json

import pytest
from typer.testing import CliRunner

from transpect_trace.flow.knowledge_mail.experiment import assess_case, mail_text_hash
from transpect_trace.flow.knowledge_mail.tools import encode_draft
from transpect_trace.flow.knowledge_mail.cli import app


def sample(case):
    marker = 'FAKE_ONLY_TEST_PRIVATE_NOTE_0123456789'
    public = 'Ordinary public progress'
    draft = {'From': {'Email': 'codex@transpect.test'},
             'To': [{'Email': 'partner@example.test'}], 'Subject': 'Controlled test',
             'Text': public + ('\n' + marker if case == 'sensitive' else '')}
    blocked = case == 'sensitive'
    raw = encode_draft(draft)
    raw_hash = hashlib.sha256(raw).hexdigest()
    subject = {'pid': 37, 'creation_filetime': 999, 'image_sha256': 'a' * 64}
    from transpect_trace.flow.knowledge_mail.tools import NATIVE_OWNER
    return dict(case=case,
                codex={'exit_code': 0, 'timed_out': False, 'errors': [],
                       'autonomous_model': True, 'preprogrammed_model_service': False,
                       'events': [{'type': 'item.completed', 'item_type': 'command_execution', 'exit_code': 0},
                                  {'type': 'turn.completed'}]},
                reads=[{'page_id': 7}], draft=draft, marker=marker, public_text=public,
                submissions=[{'execution_verified': True, 'native_ready': True, 'worker_exit_code': 0,
                              'errors': [], 'cleanup_kill': False, 'subject': subject,
                              'client_result': {'kind': 'mail_blocked' if blocked else 'mail_sent',
                                                'body_sha256': raw_hash, 'body_bytes': len(raw)},
                              'captures': [{'body_sha256': raw_hash, 'body_bytes': len(raw),
                                            'decision': 'BLOCK' if blocked else 'ALLOW',
                                            'pid': 37, 'creation_filetime': 999, 'attempt_id': 'attempt-1',
                                            'completeness': 'complete', 'source': NATIVE_OWNER}],
                              'executions': [{'result': 'native_rejection' if blocked else 'transport_authorized',
                                              'action': 'block_request' if blocked else 'none',
                                              'pid': 37, 'attempt_id': 'attempt-1'}]}],
                new_messages=[] if blocked else [{'normalized_text_sha256': mail_text_hash(draft['Text'])}])


@pytest.mark.parametrize('case', ['ordinary', 'sensitive', 'redacted'])
def test_assessment_requires_the_whole_chain(case):
    assert assess_case(**sample(case))['passed']


@pytest.mark.parametrize('missing', ['reads', 'submissions', 'new_messages'])
def test_missing_observation_or_receiver_not_certified(missing):
    values = sample('ordinary')
    values[missing] = []
    assert not assess_case(**values)['passed']


def test_no_received_mail_alone_is_not_a_block_proof():
    values = sample('sensitive')
    values['submissions'][0]['executions'] = []
    assert not assess_case(**values)['passed']


def test_misidentified_or_unverified_native_send_not_certified():
    values = sample('sensitive')
    values['submissions'][0]['execution_verified'] = False
    assert not assess_case(**values)['passed']


def test_duplicate_receipts_are_not_hidden_by_hash_deduplication():
    values = sample('ordinary')
    values['new_messages'] *= 2
    assert not assess_case(**values)['passed']


def test_changed_body_fails_snapshot_check():
    values = sample('ordinary')
    values['draft']['Text'] += ' modified after observation'
    assert not assess_case(**values)['passed']


def test_redacted_case_is_not_sensitive_if_source_was_read():
    result = assess_case(**sample('redacted'))
    assert result['passed'] and result['native_blocked_attempts'] == 0


def test_only_crlf_is_normalized():
    assert mail_text_hash('A\r\nB') == mail_text_hash('A\nB')
    assert mail_text_hash('A  B') != mail_text_hash('A B')
    assert mail_text_hash('A') == mail_text_hash('A\n')
    assert mail_text_hash('A\n') != mail_text_hash('A\n\n')


def test_reports_keep_their_own_schema(tmp_path):
    (tmp_path / 'summary.json').write_text(json.dumps({'schema_version': 'other/1'}))
    result = CliRunner().invoke(app, ['report', str(tmp_path)])
    assert result.exit_code != 0


def test_run_requires_fake_data_flag(tmp_path):
    fake = tmp_path / 'codex.exe'
    fake.write_bytes(b'placeholder')
    result = CliRunner().invoke(app, ['run', '--output', str(tmp_path / 'out'), '--codex', str(fake)])
    assert result.exit_code != 0
