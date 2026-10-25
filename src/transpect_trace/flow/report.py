"""Read saved flow evidence without inferring runtime certification."""
import json
from pathlib import Path


def report(directory: Path):
    path = Path(directory) / 'flow-evidence.json'
    if not path.is_file():
        return {'schema_version': 'transpect.flow.report/1.0', 'status': 'unavailable',
                'limitations': ['flow_evidence_not_available'], 'can_enforce': False}
    value = json.loads(path.read_text(encoding='utf-8'))
    if value.get('schema_version') != 'transpect.flow.report/1.0' or value.get('can_enforce') is not False:
        raise ValueError('invalid flow evidence report')
    # Read-only augmentation: preserve the original evidence and explicitly link
    # independent ETW records. Do not infer events from ready/terminal health.
    runtime_path = Path(directory) / 'runtime.json'
    runtime = json.loads(runtime_path.read_text(encoding='utf-8')) if runtime_path.is_file() else {}
    coverage = runtime.get('etw_coverage')
    if coverage is not None or (Path(directory) / 'etw' / 'events.jsonl').is_file():
        value['etw_evidence'] = {
            'events_file': 'etw/events.jsonl' if (Path(directory) / 'etw' / 'events.jsonl').is_file() else None,
            'status_file': 'etw/status.json' if (Path(directory) / 'etw' / 'status.json').is_file() else None,
            'coverage': coverage,
            'can_enforce': False,
            'limitations': ['ETW access does not prove successful I/O; network activity does not prove payload delivery'],
        }
    return value
