"""Controlled two-application run; readiness gates data release, never uploads."""
from __future__ import annotations

import json
from datetime import datetime, timezone
import platform
import os
from pathlib import Path
import queue
import subprocess
import sys
import threading
import time
import traceback
from uuid import uuid4

from .manifest import load


class Fixture:
    def __init__(self, command, directory, role):
        self.role, self.directory = role, directory
        self.events = []
        self.queue = queue.Queue(maxsize=128)
        self.process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.DEVNULL, cwd=directory, creationflags=0x08000000)
        self.thread = threading.Thread(target=self._read, daemon=True)
        self.thread.start()

    def _read(self):
        try:
            while line := self.process.stdout.readline(4097):
                if len(line) > 4096:
                    raise ValueError('fixture_record_limit')
                value = json.loads(line)
                # Whitelist fixture truth. It does not certify capture or lineage.
                if not isinstance(value, dict) or value.get('kind') not in {'ready','transfer_complete','pipe_ready','received','sent','finished','error'}:
                    raise ValueError('fixture_record_kind')
                row = {k: v for k, v in value.items() if k in {'kind', 'pid', 'bytes', 'http_status', 'win32_error', 'source_access_started'}}
                for name in ('pid','bytes','http_status','win32_error'):
                    if name in row and row[name] is not None and (type(row[name]) is not int or not 0 <= row[name] <= 0xffffffff):
                        raise ValueError('fixture_record_value')
                if 'source_access_started' in row and type(row['source_access_started']) is not bool:
                    raise ValueError('fixture_record_value')
                row.update(role=self.role, evidence_origin='fixture_truth')
                self.events.append(row)
                self.queue.put_nowait(row)
        except (ValueError, OSError, queue.Full):
            try: self.queue.put_nowait({'kind': 'error'})
            except queue.Full: pass
        finally:
            try: self.queue.put_nowait({'kind': 'eof'})
            except queue.Full: pass

    def wait(self, kind, timeout=15, check=None):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if check: check()
            try: row = self.queue.get(timeout=min(.1, max(.001, deadline-time.monotonic())))
            except queue.Empty: continue
            if row['kind'] == kind: return row
            if row['kind'] in ('error', 'eof'): raise RuntimeError(f'fixture_{self.role}_failed')
        raise TimeoutError(f'fixture_{self.role}_{kind}_timeout')

    def send(self, command):
        self.process.stdin.write((command + '\n').encode('ascii'))
        self.process.stdin.flush()

    def close(self):
        if self.process.poll() is None:
            try:
                self.send('finish')
                self.process.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                # Reap only a fixture this runner launched. This is cleanup, not
                # an enforcement result or evidence of blocked transmission.
                self.process.terminate()
                self.process.wait(timeout=5)
        self.thread.join(2)
        for stream in (self.process.stdin, self.process.stdout):
            stream.close()


def run(manifest_path: Path):
    manifest, paths, output = load(manifest_path)
    output.mkdir(parents=True, exist_ok=False)
    state = {'schema_version': 'transpect.flow.runtime/1.0', 'session_id': uuid4().hex,
             'scenario': manifest.scenario, 'state': 'initializing', 'can_enforce': False,
             'data_released': False, 'gaps': [], 'fixture_exit_codes': {}, 'certified': False}
    state['started_at_utc'] = datetime.now(timezone.utc).isoformat()
    state['environment'] = {'os':platform.system(), 'os_version':platform.version(),
                            'python':platform.python_version(), 'architecture':platform.machine()}
    # Only frozen hashes and typed controls; absolute input locations/private key
    # contents and fixture source never become part of this default audit.
    state['baseline'] = {name: getattr(manifest, name).sha256 for name in paths}
    def persist():
        temporary = output / 'runtime.tmp'
        temporary.write_text(json.dumps(state, indent=2) + '\n', encoding='utf-8')
        temporary.replace(output / 'runtime.json')
    persist()
    if sys.platform != 'win32' or sys.maxsize <= 2**32:
        state.update(state='unavailable', gaps=['requires_windows_x64'])
        persist()
        return state

    from transpect_trace.observe.windows import identity, Profile
    from transpect_trace.observe.ecapture import ECaptureCollector, verify_build
    from transpect_trace.observe.pipeline import Pipeline
    from transpect_trace.observe.policy import ObservationPolicy
    from transpect_trace.protect.detection import ContentIndex
    from .evidence import FlowEvidence
    from .native import NativeIOCollector
    from .etw import MultiApplicationETWCollector, summarize_coverage
    from .origin import Origin
    origin = ecapture = pipeline = etw = evidence = None
    fixtures, collectors = {}, {}
    work = output.parent / ('synthetic-work-' + state['session_id'])
    evidence_lock = threading.RLock()
    phase = 'origin'
    try:
        controller = identity(os.getpid())
        state['controller'] = {k:v for k,v in controller.items() if k != 'image_path'}
        persist()
        phase = 'ecapture_baseline'
        capture_build = verify_build(paths['ecapture'])
        if capture_build.get('variant') != 'enhanced' or capture_build.get('protocol') != 'ECW2':
            raise ValueError('enhanced_ecapture_required')
        phase = 'origin'
        index = ContentIndex.model_validate_json(paths['content_index'].read_bytes())
        origin = Origin(paths['certificate'], paths['private_key']).start()
        work.mkdir(exist_ok=False)
        handoff = str(work / 'handoff.tmp') if manifest.scenario == 'file' else rf'\\.\pipe\TranspectFlowBusiness-{state["session_id"]}'
        common = ['--scenario', manifest.scenario, '--handoff', handoff]
        phase = 'fixtures'
        fixtures['A'] = Fixture([str(paths['python']), '-I', str(paths['participant']), *common,
                                 '--source', str(paths['source'])], output, 'A')
        fixtures['B'] = Fixture([str(paths['uploader']), *common, '--url', origin.url,
                                 '--content-type', manifest.content_type, *(['--ordinary-body'] if manifest.ordinary_body else [])], output, 'B')
        subjects = {}
        for role, fixture in fixtures.items():
            ready = fixture.wait('ready')
            if ready.get('pid') != fixture.process.pid:
                raise ValueError('fixture_redirector_not_supported_use_actual_interpreter')
            subject = identity(fixture.process.pid)
            expected = manifest.python.sha256 if role == 'A' else manifest.uploader.sha256
            if subject['image_sha256'] != expected:
                raise ValueError('fixture_actual_image_mismatch')
            subjects[role] = subject
        state['subjects'] = [{k: v for k, v in subject.items() if k != 'image_path'} | {'role': role}
                             for role, subject in subjects.items()]
        state['membership'] = 'explicit_independent_subjects_not_parent_child'
        evidence = FlowEvidence(state['session_id'], state['subjects'], index=index, directory=output)
        evidence.session.scenario = manifest.scenario
        evidence.session.build_identities = state['baseline']
        evidence.session.started_at_utc = state['started_at_utc']
        def native_event(row):
            with evidence_lock: evidence.consume_native(row)
        def body_event(event, body, observation_id):
            with evidence_lock: evidence.consume_body(event, body, observation_id)
        scopes = [{'role': 'source', 'path': str(paths['source'])},
                  {'role': 'transfer' if manifest.scenario == 'file' else 'pipe', 'path': handoff}]
        phase = 'native_io'
        for role, subject in subjects.items():
            collectors[role] = NativeIOCollector(subject, paths['observer'], paths['native_manifest'], native_event, scopes=scopes)
            collectors[role].start()
        phase = 'etw'
        members = [{k: v for k, v in subject.items() if k != 'image_path'} | {'image_name': Path(subject['image_path']).name}
                   for subject in subjects.values()]
        etw = MultiApplicationETWCollector(members, paths['etw'], output/'etw', run_id=state['session_id'],
                                           duration=min(300, manifest.timeout_seconds + 90), manifest=paths['native_manifest'])
        health = etw.start()
        if health['state'] != 'ready': raise RuntimeError('etw_unavailable')
        phase = 'ecapture'
        pipeline = Pipeline(output/'observe', ObservationPolicy(), body_sink=body_event,
                            synthetic_bodies=manifest.export_fake_bodies)
        profile = Profile(image_sha256=subjects['B']['image_sha256'], application='flow-winhttp', mode='schannel')
        ecapture = ECaptureCollector(subjects['B'], profile, paths['ecapture'], pipeline)
        ecapture.start()
        def healthy():
            ecapture.check_health()
            if etw.process.poll() is not None or etw.index.health()['state'] != 'ready':
                raise RuntimeError('etw_stopped_during_transfer')
            if any(c.status()['errors'] or c.status()['lost_events'] for c in collectors.values()):
                raise RuntimeError('native_io_failed_during_transfer')
        healthy()
        phase = 'transfer'
        state.update(state='observing', data_released=True)
        state['released_at_utc'] = datetime.now(timezone.utc).isoformat()
        persist()
        if manifest.scenario == 'file':
            fixtures['A'].send('release')
            fixtures['A'].wait('transfer_complete', manifest.timeout_seconds, healthy)
            healthy()
            fixtures['B'].send('release')
        else:
            fixtures['B'].send('release')
            fixtures['B'].wait('pipe_ready', manifest.timeout_seconds, healthy)
            healthy()
            fixtures['A'].send('release')
            fixtures['A'].wait('transfer_complete', manifest.timeout_seconds, healthy)
        fixtures['B'].wait('sent', manifest.timeout_seconds, healthy)
        state['client_send_completed'] = True
    except Exception as error:
        state['gaps'].append(f'{phase}_{type(error).__name__}')
        state['failure_phase'] = phase
        state['failure_frames'] = [{'file':Path(frame.filename).name,'line':frame.lineno,'function':frame.name}
                                   for frame in traceback.extract_tb(error.__traceback__)]
    finally:
        # Targets stay idle/alive until both in-process observers acknowledge
        # terminal health. ETW remains active until the fixtures actually exit.
        if ecapture:
            try: ecapture.close()
            except Exception: state['gaps'].append('ecapture_close_failed')
            from .ecapture_diagnostics import snapshot
            build = getattr(ecapture, '_verified_manifest', {})
            state['ecapture_diagnostics'] = snapshot(subjects['B'], paths['ecapture'].parent/'schannel_hook.dll',
                                                     build.get('artifacts_sha256', {}).get('schannel_hook.dll'))
        for role, collector in collectors.items():
            try: collector.close()
            except Exception: state['gaps'].append(f'native_io_{role}_close_failed')
        for role, fixture in fixtures.items():
            try: fixture.close()
            except Exception: state['gaps'].append(f'fixture_{role}_cleanup_failed')
            state['fixture_exit_codes'][role] = fixture.process.poll()
            if state['data_released'] and fixture.process.poll() != 0:
                state['gaps'].append(f'fixture_{role}_nonzero_exit')
            (output / f'fixture-{role}.json').write_text(json.dumps(fixture.events, indent=2)+'\n', encoding='utf-8')
        if etw:
            try: state['etw_health'] = etw.stop()
            except Exception: state['gaps'].append('etw_stop_failed')
        if origin:
            try: origin.close()
            except Exception: state['gaps'].append('origin_close_failed')
        # The only raw intermediate artifact is our controlled fake fixture,
        # outside the audit tree. Never delete arbitrary manifest input paths.
        if work.exists():
            expected = (output.parent / ('synthetic-work-' + state['session_id'])).resolve()
            if work.resolve() == expected and work.parent.resolve() == output.parent.resolve():
                try:
                    (work / 'handoff.tmp').unlink(missing_ok=True)
                    work.rmdir()
                except OSError: state['gaps'].append('synthetic_work_cleanup_failed')
        if evidence:
            for role, collector in collectors.items():
                health = collector.status()
                evidence.health(f'native-io:{role}', ready=health['ready'], terminal=health['terminal'],
                                identity_verified=health['ready'], lost_events=health['lost_events'], errors=len(health['errors']),
                                limitations=health['errors'])
            if etw:
                health = etw.index.health()
                evidence.health('etw', ready=health['ready_observed'], terminal=health['terminal_observed'],
                                identity_verified=health['ready_observed'], lost_events=health['events_lost'], limitations=health['gaps'])
                # Enrollment snapshots never satisfy actual ETW observations.
                coverage = summarize_coverage(etw.index, subjects, manifest.scenario,
                                              destination_port=origin.server.server_port if origin else None)
                state['etw_coverage'] = coverage
                state['etw_event_count'] = coverage['actual_event_count']
                for gap in coverage['gaps']: evidence.gap(gap)
            if ecapture:
                structured = getattr(ecapture, 'structured', None)
                evidence.health('ecapture', ready=bool(structured and structured.ready), terminal=bool(structured and structured.terminal),
                                identity_verified=bool(structured and structured.ready), lost_events=structured.lost if structured else 0,
                                errors=len(ecapture.errors), limitations=ecapture.errors)
            if pipeline:
                try: pipeline.finish()
                except Exception: state['gaps'].append('observe_finalize_failed')
                for gap in pipeline.gaps: evidence.gap(gap['reason'])
            if origin:
                for receipt in origin.receipts: evidence.add_receipt(receipt['body_sha256'], receipt['body_bytes'], receipt['receipt_id'])
                for error in origin.errors: evidence.gap(error)
            for gap in state['gaps']: evidence.gap(gap)
            evidence.session.ended_at_utc = datetime.now(timezone.utc).isoformat()
            result = evidence.finish()
            state['evidence_status'] = result['session']['status']
            state['coverage_gaps'] = result['coverage_gaps']
            state['state'] = result['session']['status']
        else:
            state['state'] = 'unavailable'
        if not state['data_released']: state['state'] = 'unavailable'
        state['ended_at_utc'] = datetime.now(timezone.utc).isoformat()
        # No automatic runtime certification: report the four independent axes
        # and review actual ETW/event ranges and capture evidence per experiment.
        persist()
    return state
