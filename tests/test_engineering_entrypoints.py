"""Regressions for layout changes: unrelated CWD and public schema privacy."""
import json
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]


def test_schema_generator_from_unrelated_directory_preserves_public_contracts(tmp_path):
    subprocess.run([sys.executable,str(ROOT/'scripts/generate_schemas.py'),'--output',str(tmp_path/'schemas')],cwd=tmp_path,check=True)
    for original in (ROOT/'schemas').glob('*.schema.json'):
        assert json.loads(original.read_text(encoding='utf-8'))==json.loads((tmp_path/'schemas'/original.name).read_text(encoding='utf-8'))
    subprocess.run([sys.executable,str(ROOT/'scripts/generate_schemas.py'),'--check','--output',str(tmp_path/'schemas')],cwd=tmp_path,check=True)
    target=tmp_path/'schemas/unified-llm-request-v1.schema.json'
    value=json.loads(target.read_text(encoding='utf-8'));value['unexpected_public_field']=True
    target.write_text(json.dumps(value),encoding='utf-8')
    result=subprocess.run([sys.executable,str(ROOT/'scripts/generate_schemas.py'),'--check','--output',str(tmp_path/'schemas')],cwd=tmp_path,capture_output=True)
    assert result.returncode==1


def test_legacy_builders_help_never_builds_from_foreign_cwd(tmp_path):
    for name in ('build_native.py','build_guard_native.py','build_observe_native.py','build_behavior_native.py','build_egress_native.py','build_ecapture_windows.py'):
        subprocess.run([sys.executable,str(ROOT/'scripts'/name),'--help'],cwd=tmp_path,check=True,capture_output=True)
    assert not list(tmp_path.iterdir())
