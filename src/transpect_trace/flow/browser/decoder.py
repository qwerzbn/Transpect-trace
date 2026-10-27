"""Bounded native-message decoder. No headers, URLs or plaintext in audit rows."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from uuid import uuid4
from urllib.parse import urlsplit

from transpect_trace.observe.semantics import SemanticPart
from transpect_trace.protect.detection import detect
from .models import LIMIT, BrowserRequestObservation

ID = re.compile(r'^[A-Za-z0-9_.:-]{1,128}$')
GAPS = frozenset({'queue_overflow', 'pending_overflow', 'host_disconnected', 'request_cancelled',
                 'missing_header_event', 'file_reference', 'form_data_unsupported', 'raw_unavailable',
                 'body_limit', 'capture_error', 'raw_segment_unsupported', 'headers_unavailable',
                 'encoding_unsupported', 'method_unsupported', 'worker_restarted', 'collector_stopped',
                 'pending_at_shutdown'})


def sha(data):
    return hashlib.sha256(data).hexdigest()


def loopback_origin(value):
    parsed = urlsplit(value)
    if parsed.scheme != 'https' or parsed.hostname not in {'localhost', '127.0.0.1', '::1'}:
        raise ValueError('loopback_https_required')
    if parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in {'', '/'}:
        raise ValueError('origin_only_required')
    port = parsed.port or 443
    host = '[' + parsed.hostname + ']' if parsed.hostname == '::1' else parsed.hostname
    return f'https://{host}:{port}'


class BrowserDecoder:
    def __init__(self, config, index=None):
        self.run_id = config['browser_run_id']
        self.origin = loopback_origin(config['origin'])
        self.token = config['enrollment_token']
        self.extension_id = config['extension_id']
        if not ID.fullmatch(self.run_id) or not re.fullmatch('[a-p]{32}', self.extension_id) or not re.fullmatch('[a-f0-9]{64}', self.token):
            raise ValueError('invalid_enrollment')
        self.index = index
        self.session = None
        self.sequence = 0
        self.ready = False
        self.terminal = False
        self.errors = 0
        self.lost_events = 0
        self.gaps = set()
        self.observations = 0
        self._stages = {}
        self.lifecycle = []

    def consume(self, frame):
        if not isinstance(frame, dict):
            raise ValueError('invalid_frame')
        if frame.get('protocol') != 'BWO1' or frame.get('browser_run_id') != self.run_id:
            raise ValueError('identity_mismatch')
        token = frame.get('enrollment_token')
        if not isinstance(token, str) or not hmac.compare_digest(token, self.token):
            raise ValueError('enrollment_rejected')
        session = frame.get('extension_session_id')
        sequence = frame.get('sequence')
        if not isinstance(session, str) or not ID.fullmatch(session) or type(sequence) is not int or sequence != self.sequence + 1:
            raise ValueError('sequence_or_session_invalid')
        if self.terminal:
            raise ValueError('frame_after_terminal')
        if self.session is None:
            if frame.get('kind') != 'ready' or sequence != 1 or frame.get('extension_id') != self.extension_id:
                raise ValueError('ready_identity_required')
            self.session = session
            self.ready = True
        elif session != self.session:
            raise ValueError('session_changed')
        elif frame.get('kind') == 'ready':
            raise ValueError('duplicate_ready')
        self.sequence = sequence
        kind = frame.get('kind')
        if kind in {'ready', 'terminal', 'gap'}:
            lost = frame.get('lost_events', 0)
            if type(lost) is not int or not 0 <= lost <= 1000000:
                raise ValueError('invalid_loss_counter')
            self.lost_events = max(self.lost_events, lost)
            reasons = frame.get('gaps', [])
            if not isinstance(reasons, list) or any(v not in GAPS for v in reasons):
                raise ValueError('invalid_gap')
            self.gaps.update(reasons)
            self.terminal = kind == 'terminal'
            return None
        if kind == 'lifecycle':
            request = self._request_key(frame)
            event = frame.get('event')
            if event not in {'completed', 'error', 'redirect'}:
                raise ValueError('invalid_lifecycle')
            if len(self.lifecycle) >= 4096:
                self.gaps.add('lifecycle_limit')
                return None
            self.lifecycle.append({'request_id_sha256': request, 'request_stage': frame['request_stage'],
                                   'event': event, 'can_enforce': False})
            return None
        if kind != 'request':
            raise ValueError('unsupported_frame_kind')
        request = self._request_key(frame)
        stage = frame['request_stage']
        if self._stages.get(request, 0) >= stage:
            raise ValueError('duplicate_request_stage')
        if len(self._stages) >= 4096 or self.observations >= 4096:
            raise ValueError('request_limit')
        self._stages[request] = stage
        result = self._request(frame, request)
        self.observations += 1
        return result

    @staticmethod
    def _request_key(frame):
        request = frame.get('request_id')
        stage = frame.get('request_stage')
        if not isinstance(request, str) or not ID.fullmatch(request) or type(stage) is not int or not 1 <= stage <= 4096:
            raise ValueError('invalid_request_identity')
        return sha(request.encode())

    def _request(self, frame, request):
        url = urlsplit(frame.get('url', ''))
        if loopback_origin(f'{url.scheme}://{url.netloc}') != self.origin or url.username or url.password:
            raise ValueError('target_not_enrolled')
        if url.path not in {'/upload', '/chat'}:
            raise ValueError('target_path_not_enrolled')
        method = frame.get('method')
        phase = frame.get('event_phase')
        if method not in {'POST', 'PUT'} or phase not in {'before_send_headers', 'request_aborted_before_headers'}:
            raise ValueError('invalid_request_phase')
        for field in ('tab_id', 'frame_id'):
            if type(frame.get(field)) is not int or not -1 <= frame[field] <= 2**31-1:
                raise ValueError('invalid_browser_identity')
        doc = frame.get('document_id')
        if doc is not None and (not isinstance(doc, str) or not ID.fullmatch(doc)):
            raise ValueError('invalid_document_identity')
        size = frame.get('body_bytes')
        if type(size) is not int or not 0 <= size <= 2**32:
            raise ValueError('invalid_body_length')
        encoded = frame.get('body_base64', '')
        if not isinstance(encoded, str) or len(encoded) > ((LIMIT + 2)//3)*4:
            raise ValueError('wire_body_limit')
        try:
            body = base64.b64decode(encoded, validate=True)
        except ValueError:
            raise ValueError('invalid_body_base64') from None
        if len(body) > LIMIT:
            raise ValueError('body_limit')
        reasons = frame.get('gaps', [])
        if not isinstance(reasons, list) or any(v not in GAPS for v in reasons):
            raise ValueError('invalid_gap')
        limits = sorted(set(reasons))
        raw_complete = frame.get('raw_complete') is True and len(body) == size and not limits
        content = frame.get('content_type', '')
        supplied_encoding = frame.get('content_encoding', '')
        if not isinstance(content, str) or len(content) > 128 or not isinstance(supplied_encoding, str) or len(supplied_encoding) > 64:
            raise ValueError('invalid_encoding_metadata')
        content = content.lower().split(';')[0].strip()
        content = content if content in {'text/plain', 'application/json'} else 'unsupported'
        encoding = supplied_encoding.strip().lower()
        encoding = 'identity' if encoding in {'', 'identity'} else 'unsupported'
        if content == 'unsupported': limits.append('content_type_unsupported')
        if encoding == 'unsupported': limits.append('encoding_unsupported')
        if phase != 'before_send_headers': limits.append('headers_unavailable')
        complete = raw_complete and content != 'unsupported' and encoding == 'identity' and phase == 'before_send_headers'
        parsing, findings, decoded = 'unsupported', [], None
        if complete:
            try:
                text = body.decode('utf-8-sig', errors='strict')
                value = json.loads(text) if content == 'application/json' else text
                parsing = 'json' if content == 'application/json' else 'text'
                decoded = sha(body)
                fields = [SemanticPart(location='$', representation='json' if parsing == 'json' else 'text',
                                       bytes=len(body), sha256=sha(body), inspected=True, value=value)]
                findings = detect(fields, self.index)
            except (ValueError, UnicodeError, RecursionError):
                parsing = 'failed'
                limits.append('content_inspection_failed')
        status = 'incomplete' if not complete or parsing == 'failed' else 'matched' if findings else 'no_match'
        return BrowserRequestObservation(observation_id=uuid4().hex, browser_run_id=self.run_id,
            extension_session_id=self.session, request_id_sha256=request, request_stage=frame['request_stage'],
            tab_id=frame['tab_id'], frame_id=frame['frame_id'], document_id_sha256=sha(doc.encode()) if doc else None,
            event_phase=phase, method=method, target_origin=self.origin, target_path_sha256=sha(url.path.encode()),
            content_type=content, body_bytes=size, captured_bytes=len(body), body_sha256=sha(body) if raw_complete else None,
            decoded_body_sha256=decoded, completeness='complete' if complete else 'partial',
            encoding_state=encoding, parsing_state=parsing, detection_status=status, findings=findings,
            attachment_state='reference_content_unchecked' if 'file_reference' in reasons else 'unsupported' if 'form_data_unsupported' in reasons else 'none',
            limitations=sorted(set(limits + ['network_process_unknown', 'browser_api_not_wire_or_delivery_evidence',
                                           'javascript_body_source_type_unknown', 'underlying_network_attempt_mapping_unverified'])))

    def health(self):
        return {'protocol':'BWO1', 'browser_run_id':self.run_id, 'extension_session_id':self.session,
                'ready':self.ready, 'terminal':self.terminal, 'errors':self.errors, 'lost_events':self.lost_events,
                'request_observations':self.observations, 'last_sequence':self.sequence,
                'limitations':sorted(self.gaps | (set() if self.terminal else {'terminal_missing'})),
                'can_enforce':False}
