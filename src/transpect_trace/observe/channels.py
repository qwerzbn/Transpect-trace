"""M7 routing evidence, separate from Observe v1 and enforcement certification.

Routes are recommendations for a declared experiment, never an instruction to
inject another Hook. In particular no loaded-module name proves TLS usage.
"""
from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from .unified import UnifiedLLMRequest


class CaptureHealth(BaseModel):
    model_config = ConfigDict(extra='forbid')
    schema_version: Literal['transpect.capture.health/1.0'] = 'transpect.capture.health/1.0'
    provider: Literal['ecapture-windows', 'native-observer']
    pid: int = Field(gt=0)
    creation_filetime: int = Field(gt=0)
    image_sha256: str = Field(pattern=r'^[a-f0-9]{64}$')
    collector_identity_verified: bool = False
    ready: bool = False
    terminal: bool = False
    loss: int | None = Field(default=None, ge=0)
    errors: list[str] = Field(default_factory=list)
    gaps: list[str] = Field(default_factory=list)
    # Failure to load is not proof that the client never uses Schannel.
    failure: Literal['none', 'permission', 'runtime', 'tls_backend', 'protocol', 'boundary', 'unknown'] = 'unknown'
    observation_ids: list[str] = Field(default_factory=list)


def read_records(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines() if line.strip()]


def assess_capture(directory: Path) -> dict:
    """Recompute visibility from metadata. Does not accept a summary 'passed' bit.

    The receipt file contains decoded-body hashes from the isolated origin. A
    multiset comparison verifies experiment coverage, not a per-request mapping.
    """
    health = CaptureHealth.model_validate_json((directory / 'capture-health.json').read_bytes())
    requests = [UnifiedLLMRequest.model_validate(r) for r in read_records(directory / 'unified-requests.jsonl')]
    receipts = read_records(directory / 'origin-receipts.jsonl')
    expected = Counter(r['decoded_payload_sha256'] for r in receipts)
    observed = Counter(r.decoded_payload_sha256 for r in requests)
    limitations = list(health.gaps)
    identity_ok = all((r.pid, r.creation_filetime, r.image_sha256, r.capture_source) ==
                      (health.pid, health.creation_filetime, health.image_sha256, health.provider) for r in requests)
    ids = [r.observation_id for r in requests]
    linked = len(ids) == len(set(ids)) and Counter(ids) == Counter(health.observation_ids)
    complete = bool(requests) and all(r.completeness == 'complete' and r.parsing_state == 'parsed'
                                    and r.encoding_state in {'identity', 'decoded'} and not r.limitations for r in requests)
    matched = bool(expected) and expected == observed
    healthy = (health.collector_identity_verified and health.ready and health.terminal and health.loss == 0
               and not health.errors and not health.gaps and health.failure == 'none')
    if health.provider == 'native-observer' and any(r.application == 'chrome-web' and r.capture_point == 'tls' for r in requests):
        # The research profile is not certified even if a single replay happens
        # to match. Its unresolved object lifetime cannot be waived by a file.
        healthy = False
        limitations.append('chrome_tls_adapter_not_certified')
    if healthy and identity_ok and linked and complete and matched:
        state = 'complete'
    elif requests:
        state = 'partial'
    elif health.failure in {'permission', 'runtime'} or health.errors:
        state = 'unavailable'
    elif health.failure in {'tls_backend', 'protocol'}:
        state = 'unsupported'
    else:
        state = 'unknown'
    for ok, reason in [(healthy, 'collector_health_unverified'), (identity_ok, 'capture_identity_mismatch'),
                       (linked, 'observation_health_link_missing'), (complete, 'complete_request_boundary_unverified'),
                       (matched, 'decoded_origin_hashes_unmatched')]:
        if not ok:
            limitations.append(reason)
    return {'provider': health.provider, 'status': state, 'scope': 'controlled_origin',
            'failure_reason': health.failure if health.failure != 'none' else 'runtime' if health.errors else 'unknown' if not requests else 'boundary' if not complete else 'none',
            'request_count': len(requests), 'source_hashes_matched': matched,
            'semantics_observed': sorted({f.kind for r in requests for f in r.fields}),
            'classification_counts': dict(Counter(r.classification.category for r in requests)),
            'protocols_observed': sorted({r.application_protocol for r in requests}),
            'process': {'pid': health.pid, 'creation_filetime': health.creation_filetime, 'image_sha256': health.image_sha256},
            'can_enforce': False, 'actual_ui_certified': False,
            'limitations': sorted(set(limitations)),
            'source_evidence': {'status': 'unknown', 'confidence': 'Unknown'},
            'evidence': [{'path': str(p.resolve()), 'sha256': hashlib.sha256(p.read_bytes()).hexdigest()}
                         for p in (directory / name for name in ('capture-health.json', 'unified-requests.jsonl', 'origin-receipts.jsonl')) if p.is_file()]}


def select_route(ecapture: dict, fallback: dict | None = None) -> dict:
    """Never count fallback success as eCapture success or authorize enforcement."""
    if ecapture['provider'] != 'ecapture-windows' or fallback and fallback['provider'] == 'ecapture-windows':
        raise ValueError('capture sources must be independent')
    selected = ecapture if ecapture['status'] == 'complete' else fallback if fallback and fallback['status'] == 'complete' else None
    return {'ecapture_status': ecapture['status'], 'fallback_status': fallback['status'] if fallback else 'unknown',
            'selected_observation_path': selected['provider'] if selected else None,
            'status': selected['status'] if selected else 'partial' if any(r and r['request_count'] for r in (ecapture, fallback)) else ecapture['status'],
            'can_enforce': False, 'control_status': 'requires_independent_gate_evidence',
            'scope': 'controlled_origin', 'full_channel_certified': False}


def candidate_relations(left: list[UnifiedLLMRequest], right: list[UnifiedLLMRequest]) -> list[dict]:
    """Hashes are candidates only. No runtime mapping is currently propagated.

    Bounded, metadata-only and deliberately no deduplication or policy caching.
    """
    if len(left) > 10000 or len(right) > 10000:
        raise ValueError('correlation input limit')
    index: dict[str, list[UnifiedLLMRequest]] = {}
    for request in right:
        if request.decoded_payload_sha256:
            index.setdefault(request.decoded_payload_sha256, []).append(request)
    result = []
    for request in left:
        for other in index.get(request.decoded_payload_sha256, []):
            if request.capture_source == other.capture_source or request.observation_id == other.observation_id:
                continue
            if len(result) >= 10000:
                raise ValueError('correlation edge limit')
            result.append({'left_id': request.observation_id, 'right_id': other.observation_id,
                           'grade': 'CANDIDATE', 'method': 'same_decoded_hash', 'merged': False,
                           'limitations': ['runtime_request_mapping_unavailable', 'hash_match_does_not_prove_same_request']})
    return result


def channel_matrix(manifest: Path) -> dict:
    config = json.loads(manifest.read_text(encoding='utf-8'))
    if config.get('schema_version') != 'transpect.channels.experiments/1.0':
        raise ValueError('unsupported channel manifest')
    rows = []
    for entry in config['experiments']:
        if entry['channel'] not in {'api', 'cli', 'ide', 'web-chat'}:
            raise ValueError('invalid channel')
        directories = [(manifest.parent / path).resolve() for path in entry['captures']]
        sources = [assess_capture(path) for path in directories]
        if sum(r['provider'] == 'ecapture-windows' for r in sources) != 1 or len(sources) > 2:
            raise ValueError('one eCapture attempt and at most one fallback per experiment')
        ecapture = next(r for r in sources if r['provider'] == 'ecapture-windows')
        fallback = next((r for r in sources if r['provider'] != 'ecapture-windows'), None)
        relations=[]
        if len(directories)==2:
            observations=[[UnifiedLLMRequest.model_validate(r) for r in read_records(path/'unified-requests.jsonl')] for path in directories]
            relations=candidate_relations(*observations)
        rows.append({'channel': entry['channel'], 'captures': sources, 'route': select_route(ecapture, fallback),
                     'cross_source_relations':relations, 'logical_requests_merged':0})
    return {'schema_version': 'transpect.channels.matrix/1.0', 'experiments': rows,
            'missing_channels': sorted({'api', 'cli', 'ide', 'web-chat'} - {r['channel'] for r in rows}),
            'overall_complete': False, 'limitations': ['real_UI_and_enforcement_require_separate_acceptance',
                                                      'ETW_source_evidence_not_certified']}
