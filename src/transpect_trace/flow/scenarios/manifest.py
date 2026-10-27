"""Frozen inputs for fixed, local business experiments, never shell commands."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from transpect_trace.flow.manifest import FrozenFile
from .models import Token

CODEX_SHA256 = 'd13914ced6c7af174d8d638db938284231227312104b06a25e9608c632a7daec'
CASES = {'webhook': {'plain', 'nested', 'extract', 'public', 'retry'},
         'git': {'sensitive', 'public', 'untracked', 'old_commit', 'deleted_history', 'reject_ref', 'repeat'}}
BUILD_KEYS = {'guard_dll', 'io_observer', 'native_manifest', 'etw', 'ecapture',
              'ecapture_manifest', 'behavior_etw'}


class ScenarioParticipant(BaseModel):
    model_config = ConfigDict(extra='forbid')
    role: Token
    kind: Literal['real_application', 'controlled_service', 'test_program']
    executable_key: Token | None = None


class ScenarioStep(BaseModel):
    model_config = ConfigDict(extra='forbid')
    step_id: Token
    kind: Literal['source_export', 'tool_execution', 'transform', 'upload', 'commit', 'push']
    participant: Token


def default_participants(scenario):
    result = [ScenarioParticipant(role='exporter', kind='test_program', executable_key='python'),
              ScenarioParticipant(role='codex', kind='real_application', executable_key='codex'),
              ScenarioParticipant(role='transformer', kind='real_application',
                                  executable_key='powershell' if scenario == 'webhook' else 'python'),
              ScenarioParticipant(role='origin', kind='controlled_service')]
    if scenario == 'git':
        result.append(ScenarioParticipant(role='git-helper', kind='real_application', executable_key='git'))
    return result


def default_steps(scenario):
    result = [ScenarioStep(step_id='export', kind='source_export', participant='exporter'),
              ScenarioStep(step_id='tool', kind='tool_execution', participant='codex'),
              ScenarioStep(step_id='transform', kind='transform', participant='transformer')]
    if scenario == 'webhook':
        result.append(ScenarioStep(step_id='upload', kind='upload', participant='transformer'))
    else:
        result += [ScenarioStep(step_id='commit', kind='commit', participant='git-helper'),
                   ScenarioStep(step_id='push', kind='push', participant='git-helper')]
    return result


class BusinessScenarioManifest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    schema_version: Literal['transpect.business.manifest/1.0'] = 'transpect.business.manifest/1.0'
    scenario: Literal['webhook', 'git']
    case: Token
    fake_data_only: Literal[True]
    can_enforce: Literal[False] = False
    executables: dict[Token, FrozenFile]
    build_inputs: dict[Token, FrozenFile]
    source: FrozenFile
    content_index: FrozenFile
    certificate: FrozenFile
    private_key: FrozenFile
    output: Path
    participants: list[ScenarioParticipant] = Field(default_factory=list)
    steps: list[ScenarioStep] = Field(default_factory=list)
    timeout_seconds: int = Field(default=90, ge=30, le=180)
    git_tls_backend: Literal['default', 'schannel'] = 'default'

    @model_validator(mode='after')
    def fixed_experiment(self):
        if self.case not in CASES[self.scenario]:
            raise ValueError('unsupported_scenario_case')
        required = {'codex', 'python', 'powershell'} | ({'git'} if self.scenario == 'git' else set())
        if set(self.executables) != required:
            raise ValueError('executable_keys_mismatch')
        if set(self.build_inputs) != BUILD_KEYS:
            raise ValueError('build_input_keys_mismatch')
        if self.executables['codex'].sha256 != CODEX_SHA256:
            raise ValueError('unsupported_codex_baseline')
        if self.scenario != 'git' and self.git_tls_backend != 'default':
            raise ValueError('git_tls_setting_outside_git')
        expected_participants = default_participants(self.scenario)
        expected_steps = default_steps(self.scenario)
        if not self.participants:
            self.participants = expected_participants
        if not self.steps:
            self.steps = expected_steps
        if self.participants != expected_participants or self.steps != expected_steps:
            raise ValueError('unsupported_scenario_graph')
        return self

    def resolve(self, base: Path):
        base = Path(base).resolve()
        values = {**self.executables, **self.build_inputs,
                  **{name: getattr(self, name) for name in ('source', 'content_index', 'certificate', 'private_key')}}
        paths = {name: value.verify(base) for name, value in values.items()}
        if paths['source'].stat().st_size > 1024 * 1024:
            raise ValueError('source_exceeds_1_mib')
        try:
            source = json.loads(paths['source'].read_text(encoding='utf-8-sig'))
        except (ValueError, UnicodeError):
            raise ValueError('source_not_utf8_json') from None
        if not isinstance(source, dict):
            raise ValueError('source_requires_object')
        output = (base / self.output).resolve()
        if output.exists():
            raise ValueError('output_must_be_new')
        if paths['ecapture_manifest'] != paths['ecapture'].parent / 'ecapture-build.json':
            raise ValueError('ecapture_manifest_location_mismatch')
        native = json.loads(paths['native_manifest'].read_text(encoding='utf-8'))
        if native.get('protocol') != 'FIO1' or native.get('can_enforce') is not False:
            raise ValueError('native_manifest_protocol_mismatch')
        for key in ('io_observer', 'etw'):
            if native.get('artifacts', {}).get(paths[key].name, {}).get('sha256') != self.build_inputs[key].sha256:
                raise ValueError('native_artifact_manifest_mismatch')
        return paths, output


def load(path):
    path = Path(path).resolve()
    value = BusinessScenarioManifest.model_validate_json(path.read_bytes())
    paths, output = value.resolve(path.parent)
    return value, paths, output
