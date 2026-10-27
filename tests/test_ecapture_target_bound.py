"""The additive pipe patch must not weaken or replace the existing build pin."""
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from transpect_trace.observe.ecapture import PIN, target_bound_patch_manifest, verify_build

ROOT=Path(__file__).resolve().parents[1]
PATCHES=ROOT/'patches/ecapture-windows'


def fake_build(folder, *, patch_set=None):
    exe=folder/'ecapture.exe';dll=folder/'schannel_hook.dll'
    exe.write_bytes(b'controlled-fake-collector');dll.write_bytes(b'controlled-fake-dll')
    value={**PIN,'variant':'enhanced','protocol':'ECW2',
        'patches_sha256':json.loads((PATCHES/'manifest.json').read_bytes())['sha256'],
        'artifacts_sha256':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in (exe,dll)}}
    if patch_set is not None:
        value.update(patch_set=patch_set,overlays_sha256=target_bound_patch_manifest(PATCHES)['sha256'])
    return exe,value


def save(exe, value):
    (exe.parent/'ecapture-build.json').write_text(json.dumps(value),encoding='utf-8')


def test_original_enhanced_build_still_verifies_without_overlay(tmp_path):
    exe,value=fake_build(tmp_path);save(exe,value)
    assert 'patch_set' not in verify_build(exe)


def test_explicit_target_bound_build_requires_exact_additive_manifest(tmp_path):
    exe,value=fake_build(tmp_path,patch_set='target-bound-v1');save(exe,value)
    assert verify_build(exe)['patch_set']=='target-bound-v1'
    value['overlays_sha256']['target_pipe_windows.go']='0'*64;save(exe,value)
    with pytest.raises(ValueError,match='target-bound build identity'):verify_build(exe)


@pytest.mark.parametrize('change',[
    {'patch_set':'unrecognized'}, {'patch_set':None}, {'overlays_sha256':{}},
    {'variant':'upstream','protocol':'upstream-preview','patches_sha256':{}},
])
def test_variant_or_overlay_confusion_is_rejected(tmp_path,change):
    exe,value=fake_build(tmp_path,patch_set='target-bound-v1');value.update(change);save(exe,value)
    with pytest.raises(ValueError):verify_build(exe)


def test_overlay_hashes_without_explicit_patch_set_are_rejected(tmp_path):
    exe,value=fake_build(tmp_path);value['overlays_sha256']={};save(exe,value)
    with pytest.raises(ValueError):verify_build(exe)


@pytest.mark.parametrize('relative',[
    'target-bound/target_pipe_windows.go', 'target-bound/0001-target-bound-pipe.patch',
    'target-bound/target_pipe_windows_test.go', 'manifest.json',
])
def test_modified_overlay_or_base_pin_is_rejected(tmp_path,relative):
    copy=tmp_path/'patches';shutil.copytree(PATCHES,copy)
    path=copy/relative;path.write_bytes(path.read_bytes()+b'\n')
    with pytest.raises(ValueError):target_bound_patch_manifest(copy)


def test_overlay_only_replaces_pipe_security_and_keeps_peer_checks(tmp_path):
    original=(PATCHES/'enhanced/enhanced_entry_windows.go').read_bytes()
    tree=tmp_path/'derived';tree.mkdir();entry=tree/'enhanced_entry_windows.go';entry.write_bytes(original)
    patch=PATCHES/'target-bound/0001-target-bound-pipe.patch'
    subprocess.run(['git','apply','--check',str(patch)],cwd=tree,check=True,capture_output=True)
    subprocess.run(['git','apply',str(patch)],cwd=tree,check=True,capture_output=True)
    modified=entry.read_text(encoding='utf-8')
    assert 'enhancedTargetPipeSecurity(pid, birth)' in modified
    for check in ('windows.PIPE_REJECT_REMOTE_CLIENTS','windows.FILE_FLAG_FIRST_PIPE_INSTANCE',
                  'GetNamedPipeClientProcessId(pipe, &peer)','peer != pid','current != birth',
                  'process_generation_mismatch','session_random_failed','invalid_capture_frame'):
        assert check in modified
    assert (PATCHES/'enhanced/enhanced_entry_windows.go').read_bytes()==original
    with pytest.raises(subprocess.CalledProcessError):
        subprocess.run(['git','apply','--check',str(patch)],cwd=tree,check=True,capture_output=True)


def test_builder_rejects_target_overlay_for_upstream_before_building():
    result=subprocess.run([sys.executable,str(ROOT/'scripts/build_ecapture_windows.py'),
        '--variant','upstream','--target-bound-pipe'],cwd=ROOT,capture_output=True,timeout=15)
    assert result.returncode==2
    assert b'requires --variant enhanced' in result.stderr
