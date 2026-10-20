"""New detection/policy semantics behind the unchanged Guard v1 reply."""
import hashlib,time
from .models import SemanticCaptureEvent
from .policy import ProtectionEngine,ProtectionPolicy
from transpect_trace.guard.policy import GuardDecision

class GuardPolicyBridge:
    def __init__(self,subject,*,channel='cli',engine=None,run_id=None):
        if 'baseline' in subject:subject={**subject,'image_sha256':subject['baseline']['sha256']}
        self.subject,self.channel=subject,channel
        self.engine=engine or ProtectionEngine();self.policy=self.engine.policy
        self.run_id=run_id or f'{subject["pid"]}-{subject["creation_filetime"]}'

    def evaluate(self,request):
        if request.kind!='model.request':
            row={} if request.kind!='native.outcome' else {'kind':'native.outcome','request_id':request.outcome_for_request_id,
                'action':request.outcome_action,'action_execution':'native_error_constructed'}
            return GuardDecision(request_id=request.request_id,decision='allow',action='none',reason='CONTROL_ACK',policy_version=self.policy.version),row
        raw=request.payload_utf8.encode();started=time.monotonic()
        event=SemanticCaptureEvent(attempt_id=request.request_id,run_id=self.run_id,adapter_id=f'{self.channel}-guard-v1-bridge',
            application='vscode-codex' if self.channel=='ide' else 'codex-cli',channel=self.channel,pid=self.subject['pid'],
            creation_filetime=self.subject['creation_filetime'],image_sha256=self.subject['image_sha256'],protocol=request.protocol,
            completeness=request.completeness,body_sha256=hashlib.sha256(raw).hexdigest(),body_bytes=len(raw),body=raw,
            gate_owner='native-guard-v1')
        verdict=self.engine.evaluate(event)
        decision=GuardDecision(request_id=request.request_id,decision='allow' if verdict.decision=='ALLOW' else 'unknown' if verdict.decision=='UNKNOWN' else 'deny',
            action=verdict.requested_action,reason=verdict.reason,policy_version=verdict.policy_version)
        # Keep legacy source correlation and audits readable; no plaintext values.
        row={'kind':'policy.decision','request_id':request.request_id,'guard_session_id':request.guard_session_id,'pid':request.pid,'tid':request.tid,
            'protocol':request.protocol,'decision':decision.decision,'action':decision.action,'reason':decision.reason,
            'policy_version':self.policy.version,'content_sha256':event.body_sha256,'content_bytes':len(raw),
            'matched_rule_ids':sorted({f.rule_id for f in verdict.findings}),'candidate_source_paths':[],'source_confidence':'Unknown',
            'elapsed_ms':(time.monotonic()-started)*1000,'action_execution':'not_yet_confirmed','byte_level_taint_proof':False,
            'protect_verdict':verdict.model_dump()}
        # Additive metadata only; Guard v1's six-field response remains unchanged.
        from .unified import normalize
        from transpect_trace.observe.semantics import from_unified
        unified=normalize(event)
        row['unified_request']=unified.model_dump()
        row['request_semantics']=from_unified(unified,raw).model_dump()
        return decision,row
