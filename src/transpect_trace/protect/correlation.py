"""Relations never grant permission. Only a direct runtime mapping is EXACT."""
from .models import RequestRelation

class RequestCorrelator:
    def __init__(self,verified_mappings=None):
        # Only adapter-verified mappings may be supplied here. No current TLS
        # observer propagates this identity, so runtime defaults to none.
        self.verified_mappings=verified_mappings or {}
        self.events={};self.parents={};self.owners={};self.sealed=False

    def seal(self):
        """Close a bounded evidence window before asserting unique timing."""
        self.sealed=True

    def add(self,event):
        if self.sealed:raise ValueError('evidence window already closed')
        if len(self.events)>=4096:raise ValueError('correlation window limit')
        if event.observation_id in self.events:raise ValueError('duplicate observation identity')
        key=(event.run_id,event.attempt_id)
        if event.gate_owner:
            if key in self.owners:raise ValueError('sending attempt already has a gate owner')
            self.owners[key]=event.gate_owner
        self.events[event.observation_id]=event.model_copy(update={'body':b''})
        self.parents[event.observation_id]=event.observation_id

    def relate(self,left,right,*,direct_mapping_evidence=None):
        a,b=self.events[left],self.events[right]
        if left==right:raise ValueError('self relation')
        same_process=(a.pid,a.creation_filetime,a.run_id)==(b.pid,b.creation_filetime,b.run_id)
        # Caller must supply a verified mapping event, never an inferred hash ID.
        proof=self.verified_mappings.get(direct_mapping_evidence)
        mapping_matches=proof is not None and set(proof.get('observation_ids',[]))=={left,right} and proof.get('attempt_id')==a.attempt_id
        if mapping_matches and same_process and a.attempt_id==b.attempt_id:
            grade,method='EXACT','verified_runtime_request_mapping'
            self.parents[self.root(right)]=self.root(left)
        elif self.sealed and same_process and (a.adapter_id,a.capture_stage)!=(b.adapter_id,b.capture_stage) and not (a.gate_owner and b.gate_owner) and a.completeness==b.completeness=='complete' and a.connection_identity==b.connection_identity=='stable' and a.connection_id and a.connection_id==b.connection_id and a.stream_id==b.stream_id and a.protocol==b.protocol and a.protocol!='unknown' and a.body_sha256==b.body_sha256 and a.captured_qpc and b.captured_qpc and a.qpc_frequency==b.qpc_frequency and a.qpc_frequency:
            def near(x):
                return (x.pid,x.creation_filetime,x.run_id,x.connection_id,x.stream_id,x.protocol,x.body_sha256)==(a.pid,a.creation_filetime,a.run_id,a.connection_id,a.stream_id,a.protocol,a.body_sha256) and x.captured_qpc and x.qpc_frequency==a.qpc_frequency and abs(x.captured_qpc-a.captured_qpc)<=a.qpc_frequency/100
            unique=sum(bool(near(x)) for x in self.events.values())==2 and abs(a.captured_qpc-b.captured_qpc)<=a.qpc_frequency/100
            grade,method=('STRONG','closed_window_unique_process_connection_stream_body_time') if unique else ('CANDIDATE','ambiguous_same_body_timing')
        elif a.body_sha256==b.body_sha256:
            grade,method='CANDIDATE','body_hash_only'
        else:grade,method='UNKNOWN','no_direct_mapping'
        return RequestRelation(left_id=left,right_id=right,grade=grade,method=method,
            evidence_ids=[direct_mapping_evidence] if grade=='EXACT' else [],
            limitations=[] if grade=='EXACT' else ['independent_observations_not_merged'])

    def root(self,ident):
        while self.parents[ident]!=ident:ident=self.parents[ident]
        return ident
