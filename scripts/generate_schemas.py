from __future__ import annotations

import argparse
import json
from pathlib import Path

from transpect_trace.guard.policy import GuardRequest, GuardDecision, GuardPolicy
from transpect_trace.observe.models import CaptureEvent,RequestObservation,RiskAssessment,SourceRelation
from transpect_trace.observe.policy import ObservationPolicy
from transpect_trace.observe.windows import Profile
from transpect_trace.protect.models import AdapterCapability,SemanticCaptureEvent,RequestRelation,DetectionFinding,PolicyVerdict,GateRequest,GateReply,ExecutionEvidence
from transpect_trace.protect.detection import ContentIndex
from transpect_trace.protect.policy import ProtectionPolicy
from transpect_trace.observe.classification import TrafficClassification
from transpect_trace.observe.unified import UnifiedLLMRequest
from transpect_trace.observe.semantics import RequestSemantics
from transpect_trace.observe.channels import CaptureHealth
from transpect_trace.behavior.models import BehaviorEvent, EgressRule


def generated_schemas():
    yield "codex-behavior-v1.schema.json", BehaviorEvent.model_json_schema()
    yield "codex-egress-rule-v1.schema.json", EgressRule.model_json_schema()
    for name, model in (("guard-request-v1.schema.json", GuardRequest),
                        ("guard-decision-v1.schema.json", GuardDecision),
                        ("guard-policy-v1.schema.json", GuardPolicy),
                        ("observe-capture-v1.schema.json",CaptureEvent),
                        ("observe-request-v1.schema.json",RequestObservation),
                        ("observe-risk-v1.schema.json",RiskAssessment),
                        ("observe-source-v1.schema.json",SourceRelation),
                        ("observe-policy-v1.schema.json",ObservationPolicy),
                        ("observe-profile-v1.schema.json",Profile),
                        ("capture-health-v1.schema.json",CaptureHealth),
                        ("protect-capability-v1.schema.json",AdapterCapability),
                        ("protect-semantic-v1.schema.json",SemanticCaptureEvent),
                        ("protect-relation-v1.schema.json",RequestRelation),
                        ("protect-finding-v1.schema.json",DetectionFinding),
                        ("protect-verdict-v1.schema.json",PolicyVerdict),
                        ("protect-request-v1.schema.json",GateRequest),
                        ("protect-reply-v1.schema.json",GateReply),
                        ("protect-execution-v1.schema.json",ExecutionEvidence),
                        ("protect-index-v1.schema.json",ContentIndex),
                        ("protect-policy-v1.schema.json",ProtectionPolicy),
                        ("llm-classification-v1.schema.json",TrafficClassification)):
        yield name, model.model_json_schema()
    # Public exports deliberately exclude in-memory semantic values.
    yield "unified-llm-request-v1.schema.json", UnifiedLLMRequest.model_json_schema(mode="serialization")
    yield "request-semantics-v1.schema.json", RequestSemantics.model_json_schema(mode="serialization")


def main() -> None:
    canonical=Path(__file__).resolve().parents[1]/"schemas"
    parser=argparse.ArgumentParser(description="Generate public models or check drift without writing files.")
    parser.add_argument('--output',type=Path,default=canonical)
    parser.add_argument('--check',action='store_true')
    args=parser.parse_args();root=args.output.resolve()
    generated=dict(generated_schemas())
    if args.check:
        from jsonschema import Draft202012Validator
        failures=[]
        for name,expected in generated.items():
            path=root/name
            if not path.is_file() or json.loads(path.read_text(encoding='utf-8'))!=expected:failures.append(name)
        for path in root.glob('*.schema.json'):
            Draft202012Validator.check_schema(json.loads(path.read_text(encoding='utf-8')))
            if path.name not in generated:failures.append(path.name)
        print(json.dumps({'schemas':len(generated),'drift':sorted(set(failures))},indent=2))
        if failures:raise SystemExit(1)
        return
    root.mkdir(parents=True,exist_ok=True)
    for name,schema in generated.items():
        (root/name).write_text(json.dumps(schema,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')


if __name__ == "__main__":
    main()

