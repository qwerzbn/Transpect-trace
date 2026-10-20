"""Optional passive eCapture evidence for existing controlled Native fixtures."""
import json
from pathlib import Path

from transpect_trace.guard.policy import GuardPolicy
from transpect_trace.observe.channels import CaptureHealth, assess_capture
from transpect_trace.observe.ecapture import ECaptureCollector, verify_build
from transpect_trace.observe.pipeline import Pipeline
from transpect_trace.observe.windows import discover_profile
from transpect_trace.protect.discovery import snapshot

from _build_support import ROOT


class PassiveComparison:
    def __init__(self, pid, application, directory, *, elevate=False):
        self.root=Path(directory);self.pipeline=Pipeline(self.root,GuardPolicy())
        self.subject,self.profile=discover_profile(pid,application,mode='schannel')
        self.collector=None;self.errors=[];self.failure='none';self.verified=False
        self.elevate=elevate

    def start(self):
        try:
            (self.root/'discovery-before.json').write_text(json.dumps(snapshot(self.subject['pid']),indent=2)+'\n')
            executable=ROOT/'build/observe/ecapture-enhanced/ecapture.exe'
            build=verify_build(executable);self.verified=True
            (self.root/'collector-build.json').write_text(json.dumps(build,indent=2)+'\n')
            self.collector=ECaptureCollector(self.subject,self.profile,executable,self.pipeline,elevate=self.elevate)
            self.collector.start()
        except (OSError,ValueError,RuntimeError) as error:
            self.errors.append(type(error).__name__)
            self.failure='permission' if getattr(error,'winerror',None)==5 else 'runtime'
        # Observation failure must not change the existing fixture's Gate.

    def close(self):
        if self.collector:
            self.collector.close();self.errors.extend(self.collector.errors)
        self.pipeline.finish()

    def report(self, receipts):
        collector=self.collector
        ready=bool(collector and collector.ready.is_set())
        terminal=bool(collector and getattr(getattr(collector,'structured',None),'terminal',False))
        loss=getattr(getattr(collector,'structured',None),'lost',None)
        health=CaptureHealth(provider='ecapture-windows',pid=self.subject['pid'],
            creation_filetime=self.subject['creation_filetime'],image_sha256=self.subject['image_sha256'],
            collector_identity_verified=self.verified,ready=ready,terminal=terminal,loss=loss,
            errors=self.errors,gaps=[r['reason'] for r in self.pipeline.gaps],failure=self.failure,
            observation_ids=[r['observation_id'] for r in self.pipeline.rows])
        (self.root/'capture-health.json').write_text(health.model_dump_json(indent=2)+'\n')
        # The existing fake Codex origin receives uncompressed JSON in these fixtures.
        (self.root/'origin-receipts.jsonl').write_text(''.join(json.dumps({'decoded_payload_sha256':r['payload_sha256']})+'\n'
            for r in receipts if r.get('payload_sha256') and r.get('payload_bytes')))
        result=assess_capture(self.root)
        (self.root/'report.json').write_text(json.dumps(result,indent=2)+'\n')
        return result
