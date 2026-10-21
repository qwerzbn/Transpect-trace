import json
from pathlib import Path
import sys


def test_partial_green_summaries_cannot_certify_full_business_suite(tmp_path,monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1]/'scripts'))
    from validate_codex_scenarios import report
    for mode in ('exec','tui'):
        folder=tmp_path/mode;folder.mkdir()
        (folder/'summary.json').write_text(json.dumps({'cases':[{'case':'clean_log','protocol':'http',
            'passed':True,'sensitive_tool_result_observed':True}]}),encoding='utf-8')
    value=report(tmp_path)
    assert not value['required_control_cases_passed']
    assert not value['whole_stage_complete']
    assert not value['required_visibility_cases_passed']
    assert any(r['reason']=='required_cases_missing_or_duplicated' for r in value['gaps'])


def test_marker_or_valid_json_alone_cannot_certify_complete_capture(tmp_path,monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1]/'scripts'))
    from validate_codex_scenarios import capture_complete
    row={'source_same_layer_hash_match':True,'sensitive_tool_result_observed':True,
        'capture':{'state':'stopped','terminal_health':True,'dropped_snapshots':0,'errors':[]}}
    assert not capture_complete(tmp_path,row)


def test_prewarm_only_capture_cannot_hide_missing_tool_result_snapshot(tmp_path,monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1]/'scripts'))
    from validate_codex_scenarios import capture_complete
    guard=tmp_path/'guard';capture=guard/'capture';capture.mkdir(parents=True)
    decisions=[{'kind':'policy.decision','request_id':'prewarm','content_sha256':'a','content_bytes':10,'decision':'allow'},
        {'kind':'policy.decision','request_id':'tool-result','content_sha256':'b','content_bytes':20,'decision':'deny'}]
    (guard/'audit.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in decisions))
    frames=[{'request_id':'prewarm','payload_sha256':'a','payload_bytes':10,'completeness':'complete',
        'boundary_evidence':'versioned_immutable_request_snapshot'}]
    metadata=capture/'request-snapshots.jsonl'
    metadata.write_text(''.join(json.dumps(r)+'\n' for r in frames))
    row={'capture':{'state':'stopped','terminal_health':True,'dropped_snapshots':0,'errors':[],'observed_requests':1},
        'source_receipts':[{'payload_sha256':'a','payload_bytes':10}],'source_same_layer_hash_match':True}
    assert not capture_complete(tmp_path,row)
    frames.append(dict(frames[0],request_id='tool-result',payload_sha256='b',payload_bytes=20))
    metadata.write_text(''.join(json.dumps(r)+'\n' for r in frames));row['capture']['observed_requests']=2
    assert capture_complete(tmp_path,row)
    row['source_receipts'].append({'payload_sha256':'uninspected','payload_bytes':10})
    assert not capture_complete(tmp_path,row)
    row['source_receipts'].pop();frames[-1]['completeness']='partial'
    metadata.write_text(''.join(json.dumps(r)+'\n' for r in frames))
    assert not capture_complete(tmp_path,row)
