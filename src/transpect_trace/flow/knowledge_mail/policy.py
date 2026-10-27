"""Content policy for controlled Mailpit text-mail submissions.

Protect v1 exposes host but not actual port/path. The fixed application tool
constrains the endpoint and forbids redirects; this policy makes no claim that
Native v1 independently authenticates the destination port or URL path.
"""
from __future__ import annotations

import hashlib

from transpect_trace.observe.unified import ContentField
from transpect_trace.protect.detection import detect
from transpect_trace.protect.models import PolicyVerdict
from transpect_trace.protect.policy import ProtectionPolicy
from .tools import LIMIT, NATIVE_OWNER, ToolError, strict_json, validate_draft


class MailPolicyEngine:
    def __init__(self, index=None, *, allowed_hosts=('localhost', '127.0.0.1', '::1'),
                 allowed_sender=None, allowed_recipients=None):
        self.policy = ProtectionPolicy(version='controlled-knowledge-mail/1',
                                       allowed_hosts=list(allowed_hosts))
        self.index = index
        self.allowed_sender = allowed_sender
        self.allowed_recipients = set(allowed_recipients) if allowed_recipients is not None else None
        self.captures = []

    def evaluate(self, event):
        decision, reason, status, findings = 'UNKNOWN', 'UNINSPECTABLE_MAIL', 'incomplete', []
        raw = event.body
        valid = (event.adapter_id == NATIVE_OWNER and event.gate_owner == NATIVE_OWNER
                 and event.method == 'POST' and event.destination_host in self.policy.allowed_hosts
                 and event.capture_stage == 'before_transport' and event.completeness == 'complete'
                 and not event.limitations and event.encoding_state == 'identity'
                 and event.content_encoding == 'identity' and 0 < len(raw) <= LIMIT
                 and len(raw) == event.body_bytes and hashlib.sha256(raw).hexdigest() == event.body_sha256)
        if valid:
            try:
                draft = validate_draft(strict_json(raw))
                if (self.allowed_sender is not None and draft['From']['Email'] != self.allowed_sender):
                    raise ToolError('MAIL_SENDER_NOT_REGISTERED')
                if (self.allowed_recipients is not None
                        and any(row['Email'] not in self.allowed_recipients for row in draft['To'])):
                    raise ToolError('MAIL_RECIPIENT_NOT_REGISTERED')
                # Includes Subject and display names as well as message text:
                # moving a secret into a header must not escape inspection.
                field = ContentField(kind='unknown', location='$', bytes=len(raw),
                                     sha256=event.body_sha256, value=draft)
                findings = detect([field], self.index)
                status = 'matched' if findings else 'no_match'
                high = any(item.sensitivity in {'CONFIDENTIAL', 'SECRET'}
                           and item.strength in {'exact', 'contextual'} for item in findings)
                decision, reason = ('BLOCK', 'SENSITIVE_MAIL_CONTENT') if high else ('ALLOW', 'MAIL_CHECKS_COMPLETE')
            except Exception:
                # A required detector/plugin failure must produce an explicit
                # refusal verdict rather than escaping and killing an IPC
                # worker. Never serialize its potentially sensitive message.
                reason = 'REQUIRED_MAIL_CHECK_FAILED'
        verdict = PolicyVerdict(attempt_id=event.attempt_id, decision=decision, reason=reason,
                                policy_version=self.policy.version,
                                requested_action='none' if decision == 'ALLOW' else 'block_request',
                                detection_status=status, findings=findings)
        self.captures.append({'attempt_id': event.attempt_id, 'observation_id': event.observation_id,
                              'pid': event.pid, 'creation_filetime': event.creation_filetime,
                              'body_sha256': event.body_sha256, 'body_bytes': event.body_bytes,
                              'completeness': event.completeness, 'source': event.adapter_id,
                              'capture_layer': 'request-body', 'decision': decision,
                              'reason': reason, 'detection_status': status,
                              'findings': [item.model_dump() for item in findings],
                              'endpoint_binding': 'fixed_tool_config_only; native_v1_exposes_host_only'})
        return verdict
