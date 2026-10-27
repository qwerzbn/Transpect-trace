"""Explicit isolated Chrome discovery and Schannel feasibility, never certification by zero events."""
from __future__ import annotations

import ctypes
from ctypes import wintypes
import json
from pathlib import Path
import subprocess
import time

from .runtime import _write, digest


def _command_arguments(command):
    library = ctypes.WinDLL('shell32', use_last_error=True)
    library.CommandLineToArgvW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_int)]
    library.CommandLineToArgvW.restype = ctypes.POINTER(wintypes.LPWSTR)
    count = ctypes.c_int()
    result = library.CommandLineToArgvW(command, ctypes.byref(count))
    if not result: raise OSError('command_line_unavailable')
    try: return [result[i] for i in range(count.value)]
    finally:
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.LocalFree.argtypes = [ctypes.c_void_p]
        kernel.LocalFree(result)


def discover_browser(directory, root_pid):
    from transpect_trace.observe.windows import identity
    from transpect_trace.protect.discovery import snapshot
    directory = Path(directory)
    manifest = json.loads((directory/'experiment.json').read_text(encoding='utf-8'))
    before = identity(root_pid)
    if before['image_sha256'] != manifest['chrome']['sha256']:
        raise ValueError('chrome_identity_mismatch')
    command = subprocess.check_output(['powershell', '-NoProfile', '-Command',
        f'(Get-CimInstance Win32_Process -Filter "ProcessId={int(root_pid)}").CommandLine'], encoding='utf-8', timeout=20).strip()
    args = _command_arguments(command)
    desired = '--user-data-dir=' + manifest['profile_directory']
    if desired.casefold() not in [arg.casefold() for arg in args] or any(arg.startswith('--type=') for arg in args):
        raise ValueError('isolated_browser_root_required')
    result = snapshot(root_pid)
    if identity(root_pid) != before: raise ValueError('chrome_identity_changed')
    result.update(browser_run_id=manifest['browser_run_id'], root_identity=before,
                  actual_tls_backend='unknown', actual_tls_handshake='unverified', can_enforce=False)
    _write(directory/'discovery.json', result)
    return result


def probe_ecapture(directory, *, root_pid, network_pid, ecapture, duration=15, elevate=False):
    from transpect_trace.observe.windows import identity, Profile
    from transpect_trace.observe.ecapture import ECaptureCollector, verify_build
    from transpect_trace.observe.pipeline import Pipeline
    from transpect_trace.observe.policy import ObservationPolicy
    directory = Path(directory)
    if not 1 <= duration <= 60: raise ValueError('duration_out_of_bounds')
    output = directory/'ecapture-probe'
    if output.exists(): raise ValueError('new_capture_directory_required')
    discovery = discover_browser(directory, root_pid)
    matches = [row for row in discovery['processes'] if row.get('identity', {}).get('pid') == network_pid and row.get('role') == 'network-service']
    if len(matches) != 1: raise ValueError('explicit_network_service_required')
    subject = matches[0]['identity']
    if identity(network_pid) != subject: raise ValueError('network_identity_changed')
    build = verify_build(Path(ecapture))
    if build.get('variant') != 'enhanced' or build.get('protocol') != 'ECW2':
        raise ValueError('enhanced_ecapture_required')
    output.mkdir()
    pipeline = Pipeline(output/'observe', ObservationPolicy())
    collector = ECaptureCollector(subject, Profile(application='controlled-chrome', mode='schannel',
        image_sha256=subject['image_sha256']), Path(ecapture), pipeline, elevate=elevate)
    result = {'schema_version':'transpect.browser.ecapture-probe/1.0', 'status':'unavailable',
        'collector_sha256':digest(ecapture), 'collector_build_sha256':digest(Path(ecapture).with_name('ecapture-build.json')),
        'subject':subject, 'requested_backend_probe':'schannel', 'actual_tls_backend':'unknown',
        'ready':False, 'terminal':False, 'lost_events':0, 'errors':[], 'request_count':0,
        'can_enforce':False, 'browser_extension_results_included':False, 'certified':False,
        'limitations':['module_presence_not_tls_use', 'zero_events_not_backend_unsupported',
                       'manual_request_and_origin_equivalence_required', 'default_chrome_path_not_certified']}
    try:
        collector.start()
        _write(output/'ready.json', {'ready':True, 'subject':subject, 'can_enforce':False})
        deadline = time.monotonic() + duration
        while time.monotonic() < deadline:
            collector.check_health()
            time.sleep(0.1)
    except (OSError, ValueError, RuntimeError):
        result['errors'].append('collector_start_or_runtime_unavailable')
    finally:
        collector.close()
        pipeline.finish()
        structured = getattr(collector, 'structured', None)
        result.update(ready=bool(structured and structured.ready), terminal=bool(structured and structured.terminal),
                      lost_events=structured.lost if structured else 0, request_count=len(pipeline.rows))
        result['errors'] = sorted(set(result['errors'] + collector.errors))
        result['native_initialization'] = collector.native_initialization
        if result['ready'] and result['terminal'] and not result['errors'] and not result['lost_events']:
            result['status'] = 'partial' if pipeline.rows else 'unknown'
        _write(output/'report.json', result)
    return result
