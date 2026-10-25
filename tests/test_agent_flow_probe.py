"""Probe acceptance logic using synthetic report data, not collection proof."""
import json
from pathlib import Path

import pytest


@pytest.fixture
def probe(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / 'scripts'))
    import probe_cross_agent_flow
    return probe_cross_agent_flow


def evidence(probe, *, message_sensitive=True, outbound_sensitive=True):
    findings = [{'registration_id':probe.REGISTRATION,'data_types':['registered_text']},
                {'registration_id':None,'data_types':['credential']}]
    def content(sensitive):
        return {'detection_status':'matched' if sensitive else 'no_match','findings':findings if sensitive else []}
    subjects = [{'role':role,'pid':pid,'creation_filetime':1000+pid,'image_sha256':'a'*64}
                for role,pid in [('A',11),('B',12)]]
    stages = [('source_read',True),('message_write',message_sensitive),
              ('message_read',message_sensitive),('outbound',outbound_sensitive)]
    outbound = {'provider':'ecapture-windows','capture_layer':'tls','completeness':'complete',
                'encoding_state':'identity','send_evidence':'encryption_input_observed',
                'decoded_body_sha256':'b'*64,'body_bytes':42,**content(outbound_sensitive)}
    health = {name:{'ready':True,'terminal':True,'identity_verified':True,'lost_events':0,'errors':0,'limitations':[]}
              for name in ('native-io:A','native-io:B','etw','ecapture')}
    flow = {'session':{'status':'complete','health':health},'collection_coverage':{'complete':True},
            'content_detection':{'outbound':[outbound]},'coverage_gaps':[],
            'origin_receipts':{'receipts':[{'body_sha256':'b'*64,'body_bytes':42,'evidence_source':'controlled_origin'}]},
            'can_enforce':False,'blocked_requests':0}
    agents = {'session':{'status':'complete','subjects':subjects},'coverage_gaps':[],
              'observations':[{'stage':stage,'body_sha256':'b'*64,'body_bytes':42,**content(sensitive)}
                              for stage,sensitive in stages],
              'relations':[{'relation_kind':kind,'confidence':'Medium'}
                           for kind in ('agent_message_handoff','protocol_parent_reference')],
              'can_enforce':False,'blocked_requests':0}
    runtime = {'state':'complete','client_send_completed':True,'can_enforce':False,'baseline':{'python':'a'*64},
               'etw_event_count':4,'etw_coverage':{'gaps':[]},'gaps':[],'coverage_gaps':[]}
    return runtime,flow,agents


def evaluate(probe, folder, runtime, flow, agents, *, message_sensitive=True, outbound_sensitive=True):
    folder.mkdir(exist_ok=True)
    (folder/'flow-evidence.json').write_text(json.dumps(flow),encoding='utf-8')
    (folder/'agent-evidence.json').write_text(json.dumps(agents),encoding='utf-8')
    return probe.evaluate_case('synthetic',runtime,folder,message_sensitive=message_sensitive,
                               outbound_sensitive=outbound_sensitive)


@pytest.mark.parametrize('label', list(('copy_sensitive','nested_sensitive','extractive_sensitive','a_public','b_public')))
def test_positive_and_both_negative_workflows_validate_stage_findings(tmp_path, probe, label):
    _,_,message_sensitive,outbound_sensitive = probe.CASES[label]
    rows = evidence(probe,message_sensitive=message_sensitive,outbound_sensitive=outbound_sensitive)
    result = evaluate(probe,tmp_path,*rows,message_sensitive=message_sensitive,outbound_sensitive=outbound_sensitive)
    assert result['passed'], result['gaps']
    assert bool(result['final_findings']) is outbound_sensitive


@pytest.mark.parametrize('fault', ['missing_tls','duplicate_receipt','missing_agent_outbound','etw_zero',
    'missing_terminal','io_loss','same_pid','different_executable','no_credential','no_registration'])
def test_missing_or_inconsistent_evidence_cannot_pass(tmp_path, probe, fault):
    runtime,flow,agents = evidence(probe)
    if fault == 'missing_tls': flow['content_detection']['outbound'] = []
    elif fault == 'duplicate_receipt': flow['origin_receipts']['receipts'] *= 2
    elif fault == 'missing_agent_outbound': agents['observations'] = agents['observations'][:-1]
    elif fault == 'etw_zero': runtime['etw_event_count'] = 0
    elif fault == 'missing_terminal': flow['session']['health']['ecapture']['terminal'] = False
    elif fault == 'io_loss': flow['session']['health']['native-io:B']['lost_events'] = 1
    elif fault == 'same_pid': agents['session']['subjects'][1]['pid'] = 11
    elif fault == 'different_executable': agents['session']['subjects'][1]['image_sha256'] = 'c'*64
    elif fault == 'no_credential': agents['observations'][-1]['findings'] = [agents['observations'][-1]['findings'][0]]
    elif fault == 'no_registration': agents['observations'][-1]['findings'] = [agents['observations'][-1]['findings'][1]]
    result = evaluate(probe,tmp_path,runtime,flow,agents)
    assert not result['passed'] and result['gaps']


@pytest.mark.parametrize('public_handoff', [True,False])
def test_negative_final_findings_cannot_be_inherited_from_sensitive_read(tmp_path, probe, public_handoff):
    runtime,flow,agents = evidence(probe,message_sensitive=not public_handoff,outbound_sensitive=False)
    agents['observations'][-1]['findings'] = agents['observations'][0]['findings']
    result = evaluate(probe,tmp_path,runtime,flow,agents,message_sensitive=not public_handoff,outbound_sensitive=False)
    assert not result['passed'] and not result['checks']['outbound_expected']


def test_privacy_scan_excludes_only_explicit_fake_inputs(tmp_path, probe):
    inputs = tmp_path/'explicit-fake-inputs'
    inputs.mkdir()
    (inputs/'source.json').write_text(probe.SECRET,encoding='utf-8')
    assert probe.privacy_scan(tmp_path,skip_fake_inputs=True)['passed']
    audit = tmp_path/'audit'
    audit.mkdir()
    (audit/'accidental.bin').write_bytes(probe.MARKER.encode('utf-16-le'))
    scan = probe.privacy_scan(tmp_path,skip_fake_inputs=True)
    assert not scan['passed'] and scan['files_with_test_secret'] == ['audit/accidental.bin']
    assert probe.SECRET not in json.dumps(scan) and probe.MARKER not in json.dumps(scan)
