"""Language-neutral policy semantics; decisions do not claim action execution."""
import hashlib,json,threading
from pydantic import Field
from .models import Record,PolicyVerdict
from .detection import detect
from transpect_trace.observe.classification import classify
from transpect_trace.observe.unified import extract_fields

class ProtectionPolicy(Record):
    version: str='protect/1'
    allowed_hosts: list[str]=Field(default_factory=list)
    review_rules: list[str]=Field(default_factory=list)
    deny_action: str='block_request'
    pii_rules: bool=False

class ProtectionEngine:
    def __init__(self,policy=None,index=None):
        self.policy=policy or ProtectionPolicy();self.index=index;self.blocked_runs=set();self.lock=threading.Lock()
        if self.policy.deny_action not in {'block_request','block_session','terminate_process'}:raise ValueError('unsupported action')

    def evaluate(self,event):
        findings=[];decision='UNKNOWN';reason='UNINSPECTABLE_CONTENT';status='incomplete'
        raw=event.body
        if event.run_id in self.blocked_runs:
            decision,reason='BLOCK','SESSION_BLOCKED'
        elif event.completeness=='complete' and not event.limitations and event.encoding_state in {'identity','decoded','compressed'} and len(raw)==event.body_bytes and hashlib.sha256(raw).hexdigest()==event.body_sha256:
            try:
                from .unified import normalize
                unified=normalize(event);fields=unified.fields;category=unified.classification
                if category.category=='LLM':
                    findings=detect(fields,self.index,pii_rules=self.policy.pii_rules)
                    status='matched' if findings else 'no_match'
                    if any(f.sensitivity in {'SECRET','CONFIDENTIAL'} and f.strength in {'exact','contextual'} for f in findings):
                        decision,reason='BLOCK','SENSITIVE_CONTENT'
                    elif any(f.rule_id in self.policy.review_rules for f in findings):decision,reason='REVIEW','POLICY_REVIEW_DENIED'
                    elif any(not f.inspected and f.kind not in {'attachment_inline','attachment_reference'} for f in fields) or not any(f.inspected and f.kind!='tool_definition' for f in fields):
                        reason='SEMANTICS_UNKNOWN'
                    elif self.policy.allowed_hosts and event.destination_host not in self.policy.allowed_hosts:
                        decision,reason='UNKNOWN','DESTINATION_NOT_ALLOWED_OR_UNKNOWN'
                    else:decision,reason='ALLOW','REQUIRED_CHECKS_COMPLETE'
                elif category.category=='NON_LLM':decision,reason,status='ALLOW','EXPLICIT_NON_LLM','no_match'
                else:reason='LLM_TARGET_UNKNOWN'
            except (ValueError,TypeError,RecursionError):reason='REQUIRED_CHECK_FAILED'
        action='none' if decision=='ALLOW' else self.policy.deny_action if decision=='BLOCK' else 'block_request'
        if action=='block_session':
            with self.lock:self.blocked_runs.add(event.run_id)
        return PolicyVerdict(attempt_id=event.attempt_id,decision=decision,reason=reason,
            policy_version=self.policy.version,requested_action=action,detection_status=status,findings=findings)
