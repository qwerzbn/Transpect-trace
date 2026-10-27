"""Narrow ordinary JSON upload policy; independent from LLM classification.

The transport adapter supplies an immutable body, not a default audit summary.
This does not turn Flow's observation or candidate relations into enforcement.
"""
from __future__ import annotations

import hashlib
import json

from transpect_trace.observe.unified import ContentField
from transpect_trace.protect.detection import detect
from transpect_trace.protect.models import PolicyVerdict
from transpect_trace.protect.policy import ProtectionPolicy

LIMIT = 1024 * 1024


class FileUploadPolicyEngine:
    def __init__(self, index=None):
        self.policy = ProtectionPolicy(version='controlled-file-upload/1', allowed_hosts=['localhost'])
        self.index = index
        self.captures = []

    def evaluate(self, event):
        decision, reason, status, findings = 'UNKNOWN', 'UNINSPECTABLE_UPLOAD', 'incomplete', []
        raw = event.body
        valid = (event.adapter_id == 'python-httpx-outbound-native/1'
                 and event.method in {'POST', 'PUT'} and event.destination_host == 'localhost'
                 and event.capture_stage == 'before_transport'
                 and event.completeness == 'complete' and not event.limitations
                 and event.encoding_state == 'identity' and event.content_encoding == 'identity'
                 and 0 < len(raw) <= LIMIT and len(raw) == event.body_bytes
                 and hashlib.sha256(raw).hexdigest() == event.body_sha256)
        if valid:
            try:
                text = raw.decode('utf-8', errors='strict')
                # Duplicate keys, non-finite numbers and parser failures are not
                # silently accepted as fully checked structured content.
                def pairs(items):
                    result = {}
                    for key, value in items:
                        if key in result:
                            raise ValueError('duplicate_json_key')
                        result[key] = value
                    return result
                value = json.loads(text, object_pairs_hook=pairs,
                                   parse_constant=lambda _: (_ for _ in ()).throw(ValueError('invalid_number')))
                if not isinstance(value, (dict, list)):
                    raise ValueError('unsupported_json_root')
                field = ContentField(kind='unknown', location='$', bytes=len(raw),
                                     sha256=event.body_sha256, value=value)
                findings = detect([field], self.index)
                status = 'matched' if findings else 'no_match'
                high = any(f.sensitivity in {'CONFIDENTIAL', 'SECRET'}
                           and f.strength in {'exact', 'contextual'} for f in findings)
                decision, reason = ('BLOCK', 'SENSITIVE_CONTENT') if high else ('ALLOW', 'REQUIRED_CHECKS_COMPLETE')
            except (UnicodeError, ValueError, TypeError, RecursionError):
                reason = 'REQUIRED_UPLOAD_CHECK_FAILED'
        verdict = PolicyVerdict(attempt_id=event.attempt_id, decision=decision, reason=reason,
                                policy_version=self.policy.version,
                                requested_action='none' if decision == 'ALLOW' else 'block_request',
                                detection_status=status, findings=findings)
        self.captures.append(dict(attempt_id=event.attempt_id, observation_id=event.observation_id,
                                  pid=event.pid, creation_filetime=event.creation_filetime,
                                  body_sha256=event.body_sha256, body_bytes=event.body_bytes,
                                  completeness=event.completeness, source=event.adapter_id,
                                  capture_layer='request-body', decision=decision, detection_status=status,
                                  findings=[f.model_dump() for f in findings]))
        return verdict
