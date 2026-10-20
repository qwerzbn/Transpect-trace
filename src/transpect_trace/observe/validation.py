"""Explicit experiment manifests; absence of capture is never absence of egress."""
from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def records(path):
    return [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines() if line.strip()] if path.is_file() else []


def validate_manifest(manifest: Path, root: Path):
    config=json.loads(manifest.read_text(encoding='utf-8'))
    if config.get('schema_version')!='transpect.ecapture.experiments/1.0':
        raise ValueError('unsupported_experiment_manifest')
    matrix=[]
    for entry in config['experiments']:
        if entry['channel'] not in {'api','cli','ide','web-chat','baseline'}:
            raise ValueError('invalid_experiment_channel')
        folder=root/entry['directory']
        summary_path=folder/'summary.json'
        summary=json.loads(summary_path.read_text(encoding='utf-8'))
        observations=records(folder/'observations.jsonl')
        unified=records(folder/'unified-requests.jsonl')
        classified=records(folder/'classifications.jsonl')
        gaps=records(folder/'coverage-gaps.jsonl')
        receipts=records(folder/'origin-receipts.jsonl')
        health=records(folder/'collector-health.jsonl')
        expected=Counter(r['payload_sha256'] for r in receipts)
        received=Counter(r['content_sha256'] for r in observations if r.get('completeness')=='complete')
        source_match=bool(expected) and expected==received
        unified_match=Counter(r.get('decoded_payload_sha256') for r in unified if r.get('completeness')=='complete')==expected and bool(expected)
        linked=False
        try:
            from .models import RequestObservation
            from .classification import TrafficClassification
            from .unified import UnifiedLLMRequest
            for row in observations:RequestObservation.model_validate(row)
            for row in unified:UnifiedLLMRequest.model_validate(row)
            for row in classified:TrafficClassification.model_validate(row)
            obs_by_id={r['observation_id']:r for r in observations}
            class_by_id={r['observation_id']:r for r in classified}
            ids=[r['observation_id'] for r in unified]
            linked=(len(set(ids))==len(ids)==len(observations)==len(classified) and set(ids)==set(obs_by_id)==set(class_by_id))
            linked=linked and all(r['classification']==class_by_id[r['observation_id']] and
                r['decoded_payload_sha256']==obs_by_id[r['observation_id']]['content_sha256'] and
                all(r[k]==obs_by_id[r['observation_id']][k] for k in ('pid','creation_filetime','connection_id','stream_id'))
                for r in unified)
        except (ValueError,KeyError,TypeError):
            linked=False
        # Upstream previews, Native comparisons and manual claims cannot certify
        # the enhanced eCapture runtime. Verify the actual evidence records too.
        observed_by_ecapture=bool(observations) and all(r.get('provider')=='ecapture-windows' and r.get('can_enforce') is False for r in observations)
        process=summary.get('process') or {}
        terminal_proof=(len(health)==2 and [r.get('kind') for r in health]==['ready','terminal'] and
            len({r.get('session') for r in health})==1 and all(r.get('protocol')=='ECW2' and r.get('lost')==0 and
            r.get('pid')==process.get('pid') and r.get('creation_filetime')==process.get('creation_filetime') for r in health))
        healthy=terminal_proof and summary.get('terminal_health_confirmed') is True and not summary.get('collector_errors') and not gaps
        passed=(source_match and observed_by_ecapture and healthy and summary.get('collector_variant')=='enhanced'
                and summary.get('runtime_available') is True)
        requested=summary.get('capture_status','not_verified')
        status='supported' if passed else requested if requested in {'unsupported','unavailable'} and not observations else 'partial' if observations else 'not_verified'
        row={'channel':entry['channel'],'scope':summary.get('scope','unknown'),'status':status,
             'process':process,'tls_backend':summary.get('tls_backend','unknown'),
             'protocol':summary.get('protocol','unknown'),'destination':summary.get('destination'),
             'payload_size':summary.get('payload_size'),'collector_variant':summary.get('collector_variant','unknown'),
             'origin_payloads':sum(expected.values()),'source_hashes_matched':source_match,
             'coverage_gaps':len(gaps),'limitations':summary.get('limitations',[]),
             'classification_counts':dict(Counter(r['category'] for r in classified)),
             'parsing_status':'passed' if passed and unified_match and linked and all(r['parsing_state']=='parsed' for r in unified)
                 and len(classified)==len(unified)==sum(expected.values()) else 'not_verified',
             'control':{'can_enforce':False,'status':'not_tested','blocked_requests':0},
             'source_evidence':{'status':'not_verified','confidence':'Unknown','byte_level_taint_proof':False},
             'actual_ai_channel_certified':False,'evidence':[]}
        for name in ('summary.json','observations.jsonl','unified-requests.jsonl','classifications.jsonl','coverage-gaps.jsonl','origin-receipts.jsonl','capture-metadata.jsonl','collector-health.jsonl'):
            path=folder/name
            if path.is_file():row['evidence'].append({'path':str(path),'sha256':digest(path)})
        matrix.append(row)
    return {'schema_version':'transpect.ecapture.matrix/1.0','manifest_sha256':digest(manifest),
            'visibility':matrix,'whole_system_coverage':False,'actual_ai_channel_certified':False,
            'notes':['Unsupported and unavailable entries do not pass plaintext acquisition.',
                     'Native comparisons and existing Guard certifications are independent.',
                     'Source correlation and request enforcement are not certified by this matrix.']}
