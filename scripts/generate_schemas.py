from __future__ import annotations

import json
from pathlib import Path

from transpect_trace.core.models import Manifest, TraceEvent
from transpect_trace.guard.policy import GuardRequest, GuardDecision, GuardPolicy
from transpect_trace.observe.models import CaptureEvent,RequestObservation,RiskAssessment,SourceRelation
from transpect_trace.observe.policy import ObservationPolicy
from transpect_trace.observe.windows import Profile


def main() -> None:
    root = Path(__file__).resolve().parents[1] / "schemas"
    root.mkdir(parents=True, exist_ok=True)
    for name, model in (("trace-event-v1.schema.json", TraceEvent), ("manifest-v1.schema.json", Manifest),
                        ("guard-request-v1.schema.json", GuardRequest),
                        ("guard-decision-v1.schema.json", GuardDecision),
                        ("guard-policy-v1.schema.json", GuardPolicy),
                        ("observe-capture-v1.schema.json",CaptureEvent),
                        ("observe-request-v1.schema.json",RequestObservation),
                        ("observe-risk-v1.schema.json",RiskAssessment),
                        ("observe-source-v1.schema.json",SourceRelation),
                        ("observe-policy-v1.schema.json",ObservationPolicy),
                        ("observe-profile-v1.schema.json",Profile)):
        (root / name).write_text(
            json.dumps(model.model_json_schema(), ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )


if __name__ == "__main__":
    main()

