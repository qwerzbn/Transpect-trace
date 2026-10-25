"""Frozen inputs for a local, observation-only two-program experiment."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field


class FrozenFile(BaseModel):
    model_config = ConfigDict(extra='forbid')
    path: Path
    sha256: str = Field(pattern=r'^[a-f0-9]{64}$')

    def verify(self, base: Path) -> Path:
        path = (base / self.path).resolve()
        if not path.is_file():
            raise ValueError('required_frozen_file_missing')
        with path.open('rb') as stream:
            actual = hashlib.file_digest(stream, 'sha256').hexdigest()
        if actual != self.sha256:
            raise ValueError('frozen_file_hash_mismatch')
        return path


class FlowManifest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    schema_version: Literal['transpect.flow.manifest/1.0'] = 'transpect.flow.manifest/1.0'
    scenario: Literal['file', 'pipe']
    fake_data_only: Literal[True]
    can_enforce: Literal[False] = False
    python: FrozenFile
    participant: FrozenFile
    uploader: FrozenFile
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
    content_type: Literal['text', 'json'] = 'text'
    ordinary_body: bool = False
    # Source files are controlled inputs, never copied to the audit directory.
    export_fake_bodies: bool = False
    timeout_seconds: int = Field(default=30, ge=10, le=90)

    def resolve(self, base: Path):
        paths = {name: value.verify(base) for name, value in self.__dict__.items() if isinstance(value, FrozenFile)}
        if paths['source'].stat().st_size > 1024 * 1024:
            raise ValueError('source_exceeds_1_mib')
        output = (base / self.output).resolve()
        if output.exists():
            raise ValueError('output_must_be_new')
        if paths['ecapture_manifest'].parent != paths['ecapture'].parent or paths['ecapture_manifest'].name != 'ecapture-build.json':
            raise ValueError('ecapture_manifest_location_mismatch')
        manifest = json.loads(paths['native_manifest'].read_text(encoding='utf-8'))
        if manifest.get('protocol') != 'FIO1' or manifest.get('can_enforce') is not False:
            raise ValueError('native_manifest_protocol_mismatch')
        for field in ('uploader', 'observer', 'etw'):
            if manifest.get('artifacts', {}).get(paths[field].name, {}).get('sha256') != getattr(self, field).sha256:
                raise ValueError('native_artifact_manifest_mismatch')
        # Only this shipped participant is certified; a manifest is not an
        # arbitrary command or script execution interface.
        if paths['participant'] != Path(__file__).with_name('participant.py').resolve():
            raise ValueError('unsupported_participant')
        return paths, output


def load(path: Path):
    path = Path(path).resolve()
    value = FlowManifest.model_validate_json(path.read_bytes())
    paths, output = value.resolve(path.parent)
    return value, paths, output


def frozen(path: Path):
    path = Path(path).resolve()
    with path.open('rb') as stream:
        return {'path': str(path), 'sha256': hashlib.file_digest(stream, 'sha256').hexdigest()}
