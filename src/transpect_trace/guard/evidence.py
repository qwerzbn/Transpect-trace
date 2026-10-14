"""Confidence of a derived relation, not a mutation of kernel event facts."""
from dataclasses import asdict, dataclass
from typing import Literal


@dataclass(frozen=True)
class SourceEvidence:
    confidence: Literal["High", "Medium", "Low", "Unknown"]
    method: str
    evidence_event_ids: tuple[str, ...]
    candidate_source_paths: tuple[str, ...]
    limitations: tuple[str, ...]
    byte_level_taint_proof: bool = False


def grade_source(*, paths=(), file_event_ids=(), process_event_ids=(), content_event_ids=(),
                 reliable_identity=False, time_related=False, dropped_events=0,
                 snapshot_current=True) -> SourceEvidence:
    paths = tuple(sorted(set(paths)))
    events = tuple(dict.fromkeys((*file_event_ids, *process_event_ids, *content_event_ids)))
    limitations = ["Not byte-level taint or unique causal provenance"]
    if dropped_events:
        limitations.append("ETW events lost; source evidence incomplete")
    if not snapshot_current:
        limitations.append("Registered snapshot may differ from the file at read time")
    if len(paths) > 1:
        limitations.append("Multiple indistinguishable source candidates")
    observed = bool(file_event_ids and process_event_ids and reliable_identity)
    if observed and content_event_ids and len(paths) == 1 and not dropped_events and snapshot_current:
        grade, method = "High", "content_match_with_file_and_process_evidence"
    elif observed and paths:
        grade, method = "Medium", "observed_lineage_and_file_access"
    elif paths and time_related:
        grade, method = "Low", "temporal_or_path_candidate"
    else:
        grade, method = "Unknown", "insufficient_evidence"
    return SourceEvidence(grade, method, events, paths, tuple(limitations))


def evidence_dict(**kwargs):
    return asdict(grade_source(**kwargs))
