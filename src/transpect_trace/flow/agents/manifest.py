"""Frozen, explicit two-test-agent experiment inputs; separate from Flow v1."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field
from ..manifest import FrozenFile


def implementation_paths():
    folder = Path(__file__).resolve().parent
    return {f'agents/{name}': folder/name for name in ('participant.py', 'protocol.py', 'winhttp.py')} | {
        'participant.py': folder.parent/'participant.py',
        'agents/__init__.py': folder/'__init__.py',
        'flow/__init__.py': folder.parent/'__init__.py',
        'transpect_trace/__init__.py': folder.parents[1]/'__init__.py'}


class AgentFlowManifest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    schema_version: Literal['transpect.agent-flow.manifest/1.0'] = 'transpect.agent-flow.manifest/1.0'
    fake_data_only: Literal[True]
    can_enforce: Literal[False] = False
    agent_kind: Literal['deterministic_test_agent'] = 'deterministic_test_agent'
    transport: Literal['local_message_pipe'] = 'local_message_pipe'
    python: FrozenFile
    participant: FrozenFile
    implementation: dict[str, FrozenFile]
    observer: FrozenFile
    etw: FrozenFile
    native_manifest: FrozenFile
    ecapture: FrozenFile
    ecapture_manifest: FrozenFile
    source: FrozenFile
    content_index: FrozenFile
    certificate: FrozenFile
    private_key: FrozenFile
    output: Path
    transform: Literal['copy', 'nested', 'extractive', 'public'] = 'copy'
    handoff_public: bool = False
    timeout_seconds: int = Field(default=30, ge=10, le=90)

    def resolve(self, base):
        paths = {name: value.verify(base) for name, value in self.__dict__.items() if isinstance(value, FrozenFile)}
        if paths['participant'] != Path(__file__).with_name('participant.py').resolve():
            raise ValueError('unsupported_agent_fixture')
        expected = implementation_paths()
        if set(self.implementation) != set(expected):
            raise ValueError('incomplete_agent_implementation_pin')
        for name, target in expected.items():
            if self.implementation[name].verify(base) != target.resolve():
                raise ValueError('unsupported_agent_implementation')
        if self.implementation['agents/participant.py'].sha256 != self.participant.sha256:
            raise ValueError('participant_identity_conflict')
        if paths['source'].stat().st_size > 1024 * 1024:
            raise ValueError('source_exceeds_limit')
        output = (base / self.output).resolve()
        if output.exists():
            raise ValueError('output_must_be_new')
        if paths['ecapture_manifest'] != paths['ecapture'].parent/'ecapture-build.json':
            raise ValueError('ecapture_manifest_location_mismatch')
        build = json.loads(paths['native_manifest'].read_text(encoding='utf-8'))
        if build.get('protocol') != 'FIO1' or build.get('can_enforce') is not False:
            raise ValueError('native_manifest_protocol_mismatch')
        for field in ('observer', 'etw'):
            if build.get('artifacts', {}).get(paths[field].name, {}).get('sha256') != getattr(self, field).sha256:
                raise ValueError('native_artifact_manifest_mismatch')
        return paths, output


def load(path):
    path = Path(path).resolve()
    manifest = AgentFlowManifest.model_validate_json(path.read_bytes())
    paths, output = manifest.resolve(path.parent)
    return manifest, paths, output
