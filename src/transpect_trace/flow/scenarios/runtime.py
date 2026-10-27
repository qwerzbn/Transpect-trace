"""Controlled real-client orchestration; observations never authorize uploads."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
from pathlib import Path
import subprocess
import sys
import threading
import time
import traceback
from uuid import uuid4

from .manifest import load
from .models import (BusinessScenarioReport, ScenarioProcess, ScenarioEvidence,
                     ScenarioStage, ScenarioOutbound, ScenarioRelation)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def dump(path, value):
    temporary = path.with_suffix(path.suffix + '.pending')
    temporary.write_text(json.dumps(value, ensure_ascii=True, indent=2) + '\n', encoding='utf-8')
    temporary.replace(path)


def ps_quote(value):
    return "'" + str(value).replace("'", "''") + "'"


def powershell_task(config, control):
    """No secret literals or untrusted script fragments enter this fixed task."""
    template = '''
$ErrorActionPreference='Stop'
$c=ConvertFrom-Json ([IO.File]::ReadAllText(__TASK_CONFIG__,[Text.Encoding]::UTF8))
$control=__TASK_CONTROL__
function Wait-Flag($name) { $d=[DateTime]::UtcNow.AddSeconds(180); while($true) { if([IO.File]::Exists((Join-Path $control 'abort'))){throw 'fixture cancelled'}; if([IO.File]::Exists((Join-Path $control $name))){return}; if([DateTime]::UtcNow -gt $d){throw 'fixture deadline'}; Start-Sleep -Milliseconds 25 } }
try {
  [IO.File]::WriteAllText((Join-Path $control 'transformer.ready.json'), ('{"pid":'+$PID+'}'))
  Wait-Flag 'transformer.release'
  $raw=[IO.File]::ReadAllText($c.incident,[Text.Encoding]::UTF8)
  $data=ConvertFrom-Json $raw
  if($c.case -eq 'public') { $value=@{report='ordinary synthetic diagnostic statistics';count=1} }
  elseif($c.case -eq 'nested') { $value=@{diagnostic=@{details=$data}} }
  elseif($c.case -eq 'extract') { $value=@{excerpt=$data.secret} }
  else { $value=$data }
  $json=ConvertTo-Json -InputObject $value -Depth 8 -Compress
  $bytes=[Text.Encoding]::UTF8.GetBytes($json)
  if($bytes.Length -gt 1048576){throw 'body limit'}
  [IO.File]::WriteAllBytes($c.generated,$bytes)
  $count=1; if($c.case -eq 'retry'){$count=2}
  $statuses=@(); $attempts=@(); $success=$true
  [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
  for($i=0;$i -lt $count;$i++) {
    try { Invoke-RestMethod -Uri $c.url -Method Post -ContentType 'application/json; charset=utf-8' -Body $bytes -TimeoutSec 15 | Out-Null; $statuses+=200; $attempts+=@{success=$true} }
    catch {
      if($c.control_action -eq 'block') {
        $success=$false; $codes=@(); $errorItem=$_.Exception
        for($depth=0;$depth -lt 10 -and $null -ne $errorItem;$depth++) {
          if($errorItem -is [Net.Sockets.SocketException]){$codes+=[int]$errorItem.NativeErrorCode}
          $errorItem=$errorItem.InnerException
        }
        $attempts+=@{success=$false;socket_errors=$codes}
      } else {
        if($c.case -ne 'retry' -or $i -ne 0 -or [int]$_.Exception.Response.StatusCode -ne 503){throw}; $statuses+=503
      }
    }
  }
  [IO.File]::WriteAllText((Join-Path $control 'transformer.done.json'),(ConvertTo-Json -Depth 5 -Compress @{success=$success;transform_success=$true;statuses=$statuses;attempts=$attempts}))
  Wait-Flag 'transformer.finish'
} catch {
  $chain=@(); $errorItem=$_.Exception
  for($depth=0;$depth -lt 10 -and $null -ne $errorItem;$depth++) {
    $item=@{type=$errorItem.GetType().FullName;hresult=[int]$errorItem.HResult}
    if($errorItem -is [Net.WebException]){$item.web_status=[int]$errorItem.Status}
    if($errorItem -is [Net.Sockets.SocketException]){$item.socket_error=[int]$errorItem.NativeErrorCode}
    $chain+=$item; $errorItem=$errorItem.InnerException
  }
  [IO.File]::WriteAllText((Join-Path $control 'transformer.error.json'),(ConvertTo-Json -Depth 5 -Compress @{error_type='PowerShellTaskFailed';exception_types=$chain}))
  try {Wait-Flag 'transformer.finish'} catch {}
  exit 2
}
'''
    return re.sub('__TASK_CONFIG__|__TASK_CONTROL__',
                  lambda match: ps_quote(config if match[0] == '__TASK_CONFIG__' else control), template)


def model_events(command, workspace, body):
    value = json.loads(body)
    if not isinstance(value, dict):
        raise ValueError('model_request_object_required')
    inputs = value.get('input', [])
    outputs = [item for item in inputs if isinstance(item,dict) and item.get('type')=='function_call_output'
               and re.fullmatch(r'call_business(?:_poll_[0-9]+)?',str(item.get('call_id','')))] if isinstance(inputs,list) else []
    latest=outputs[-1] if outputs else None
    running=re.search(r'Process running with session ID ([0-9]+)',str(latest.get('output',''))) if latest else None
    finished=bool(latest and not running)
    if finished:
        response = {'id': 'resp_business_done', 'object': 'response', 'status': 'completed',
                    'model': 'gpt-probe', 'output': [], 'usage': {'input_tokens': 1, 'output_tokens': 1, 'total_tokens': 2}}
        return [{'type': 'response.created', 'response': {**response, 'status': 'in_progress'}},
                {'type': 'response.completed', 'response': response}]
    if running:
        if len(outputs)>180: raise ValueError('fixture_tool_poll_limit')
        arguments=json.dumps({'session_id':int(running[1]),'chars':'','yield_time_ms':1000})
        name='write_stdin'; call_id='call_business_poll_'+str(len(outputs)); item_id='fc_business_poll_'+str(len(outputs))
    else:
        arguments = json.dumps({'cmd': command, 'workdir': str(workspace), 'login': False, 'yield_time_ms': 30000})
        name='exec_command'; call_id='call_business'; item_id='fc_business'
    item = {'id': item_id, 'type': 'function_call', 'status': 'completed',
            'call_id': call_id, 'name': name, 'arguments': arguments}
    response = {'id': 'resp_business', 'object': 'response', 'status': 'completed', 'model': 'gpt-probe',
                'output': [item], 'usage': {'input_tokens': 1, 'output_tokens': 1, 'total_tokens': 2}}
    return [{'type': 'response.created', 'response': {**response, 'status': 'in_progress', 'output': []}},
            {'type': 'response.output_item.added', 'output_index': 0, 'item': {**item, 'status': 'in_progress', 'arguments': ''}},
            {'type': 'response.function_call_arguments.delta', 'output_index': 0, 'item_id': item['id'], 'delta': arguments},
            {'type': 'response.function_call_arguments.done', 'output_index': 0, 'item_id': item['id'], 'name': item['name'], 'arguments': arguments},
            {'type': 'response.output_item.done', 'output_index': 0, 'item': item},
            {'type': 'response.completed', 'response': response}]


def clean_environment(home):
    denied = {'CODEX_HOME', 'CODEX_CA_CERTIFICATE', 'SSL_CERT_FILE', 'SSLKEYLOGFILE',
              'SSL_CERT_DIR', 'REQUESTS_CA_BUNDLE', 'CURL_CA_BUNDLE', 'NODE_EXTRA_CA_CERTS',
              'OPENAI_API_KEY', 'API_KEY', 'CODEX_API_KEY', 'ANTHROPIC_API_KEY', 'OPENAI_BASE_URL',
              'CHATGPT_BASE_URL', 'RUST_LOG'}
    env = {k: v for k, v in os.environ.items() if k.upper() not in denied and 'PROXY' not in k.upper()}
    env.update(CODEX_HOME=str(home), NO_PROXY='*', RUST_LOG='warn',GIT_CONFIG_NOSYSTEM='1',GIT_CONFIG_GLOBAL='NUL')
    return env


def run(manifest_path):
    # A late reporting error must not leave a saved "observing" status behind.
    # Validate the new output before entering the operation; existing folders
    # are rejected by load and are never repaired or overwritten here.
    _, _, output = load(manifest_path)
    try:
        return _run(manifest_path)
    except Exception as error:
        path = output/'runtime.json'
        if not path.is_file():
            raise
        state = json.loads(path.read_bytes())
        state.update(state='partial' if state.get('data_released') else 'unavailable', certified=False)
        state['gaps'] = sorted(set(state.get('gaps', []) + ['runtime_or_report_failed_'+type(error).__name__]))
        dump(path, state)
        return state


def run_webhook_control(manifest_path, egress_dll, action='block'):
    """Opt-in real-client experiment; does not change Observe's authority."""
    manifest, _, output = load(manifest_path)
    if manifest.scenario != 'webhook' or manifest.case not in {'plain','public'} or action not in {'allow','block'}:
        raise ValueError('unsupported_webhook_control_experiment')
    try:
        return _run(manifest_path, egress_dll=Path(egress_dll).resolve(), egress_action=action)
    except Exception as error:
        path = output/'runtime.json'
        if not path.is_file(): raise
        state = json.loads(path.read_bytes())
        state.update(state='partial', certified=False)
        state['gaps'] = sorted(set(state.get('gaps', [])+['control_report_failed_'+type(error).__name__]))
        dump(path, state)
        dump(output/'webhook-control.json', {'schema_version':'transpect.webhook-control/1.0','action':action,
             'passed':False,'checks':{'report_built':False},'error_type':type(error).__name__,
             'can_enforce':False,'scope':'explicit_codex_descendants_tcp_target'})
        return state


def _run(manifest_path, *, egress_dll=None, egress_action=None):
    manifest, paths, output = load(manifest_path)
    output.mkdir(parents=True, exist_ok=False)
    session = uuid4().hex
    state = {'schema_version': 'transpect.business.runtime/1.0', 'session_id': session,
             'scenario': manifest.scenario, 'state': 'initializing', 'controller': None,
             'data_released': False, 'certified': False, 'gaps': [], 'can_enforce': False}
    report = BusinessScenarioReport(session_id=session, scenario=manifest.scenario, case=manifest.case)
    report.stages = [ScenarioStage(stage_id=s.step_id, participant=s.participant) for s in manifest.steps]
    def persist(): dump(output / 'runtime.json', state)
    persist()
    if sys.platform != 'win32' or sys.maxsize <= 2**32:
        state.update(state='unavailable', gaps=['requires_windows_x64']); persist(); return state

    from transpect_trace.observe.windows import identity, Profile, modules
    from transpect_trace.observe.ecapture import ECaptureCollector, verify_build
    from transpect_trace.observe.pipeline import Pipeline
    from transpect_trace.observe.policy import ObservationPolicy
    from transpect_trace.observe.request_capture import GuardRequestTap
    from transpect_trace.guard.native import inject
    from transpect_trace.guard.pipe import PipeServer
    from transpect_trace.guard.policy import GuardPolicy, PolicyEngine
    from transpect_trace.protect.detection import ContentIndex, detect
    from transpect_trace.observe.unified import ContentField
    from transpect_trace.flow.native import NativeIOCollector
    from transpect_trace.flow.etw import MultiApplicationETWCollector
    from transpect_trace.flow.models import CollectorHealth
    from transpect_trace.behavior.collector import CodexBehaviorCollector
    from .sources import BusinessOrigin
    from .evidence import assess

    work = output.parent / ('fake-work-' + session)
    work.mkdir(exist_ok=False)
    workspace = work / 'workspace'; workspace.mkdir()
    control = workspace / '.control'; control.mkdir()
    home = work / 'codex-home'; home.mkdir()
    worker = Path(__file__).with_name('participant.py').resolve()
    incident, generated = workspace/'incident.json', workspace/'diagnostics.json'
    subjects, actors, io, captures = {}, {}, {}, {}
    etws, native_rows, tls_rows, object_rows, client_results = [], [], [], [], {}
    origin = server = tap = None
    egress = None
    egress_ready_before_release = False
    tool_enrolled_before_release = False
    egress_state_before_close = None
    protected_receipts = None
    unrelated_control = None
    release_git_reply = threading.Event()
    git_reply_ready = threading.Event()
    lock = threading.RLock()
    phase = 'baseline'
    finalized_captures = set()
    native_ready = False
    git_helper_hashes = {}
    index = ContentIndex.model_validate_json(paths['content_index'].read_bytes())
    task_deadline = time.monotonic() + manifest.timeout_seconds

    def remaining(maximum):
        seconds = task_deadline-time.monotonic()
        if seconds <= 0: raise TimeoutError('scenario_deadline')
        return min(maximum, seconds)

    def add(stage, provenance, process=None, **kwargs):
        item = ScenarioEvidence(evidence_id=uuid4().hex, stage_id=stage, provenance=provenance,
                                process=process, **kwargs)
        report.evidence.append(item)
        next(s for s in report.stages if s.stage_id == stage).evidence_ids.append(item.evidence_id)
        return item

    def enroll(pid, role, expected):
        subject = identity(pid)
        if subject['image_sha256'] != expected: raise ValueError('participant_image_mismatch')
        process = ScenarioProcess(role=role, **{k: subject[k] for k in ('pid', 'creation_filetime', 'image_sha256')})
        subjects[role] = subject; report.participants.append(process)
        return subject, process

    def process_for(role):
        return next(p for p in report.participants if p.role == role)

    def require_lineage(collector, process):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            with collector.lock:
                generation = collector.index.generations.get(f'{process.pid}-{process.creation_filetime}')
                parent = generation and collector.index.generations.get(generation.get('parent'))
                if generation and parent:
                    process.parent_pid = parent['subject'].pid
                    process.parent_creation_filetime = parent['subject'].creation_filetime
                    process.membership_basis = 'observed_lineage'
                    return
            time.sleep(.025)
        raise RuntimeError('tool_lineage_not_observed_before_release')

    def wait_file(name, timeout=35):
        deadline = time.monotonic() + remaining(timeout)
        while time.monotonic() < deadline:
            errors=list(control.glob('*.error.json'))
            if errors:
                for error_path in errors:
                    if error_path.name=='transformer.error.json':
                        value=json.loads(error_path.read_text(encoding='utf-8-sig'))
                        # Only exception type names and numeric codes, never a message.
                        dump(output/'tool-failure.json',{'error_type':value.get('error_type'),
                             'exception_types':value.get('exception_types',[])})
                raise RuntimeError('controlled_worker_failed')
            file = control/name
            if file.is_file(): return json.loads(file.read_text(encoding='utf-8-sig'))
            time.sleep(.025)
        raise TimeoutError('controlled_worker_deadline')

    def native_event(row):
        data = row.get('data', b'')
        clean = {k: v for k, v in row.items() if k != 'data'}
        clean['data_sha256'] = digest(data); clean['data_bytes'] = len(data)
        clean['evidence_id'] = uuid4().hex
        clean['registration_ids'] = []
        if data and row.get('success') and not row.get('capture_gap'):
            try:
                clean['registration_ids'] = [r.registration_id for r in index.matches(data.decode('utf-8'))]
            except (UnicodeError, ValueError):
                clean['content_match_unavailable'] = True
        with lock:
            if len(native_rows) >= 10000:
                if 'native_io_evidence_limit' not in state['gaps']: state['gaps'].append('native_io_evidence_limit')
                return
            native_rows.append(clean)
            with (output/'native-io.jsonl').open('a', encoding='utf-8') as out:
                out.write(json.dumps(clean, ensure_ascii=True) + '\n')

    def attach_io(role):
        item = NativeIOCollector(subjects[role], paths['io_observer'], paths['native_manifest'], native_event,
             allow_restricted_subject=role == 'transformer',
             scopes=[{'role': 'source', 'path': str(incident)}, {'role': 'transfer', 'path': str(generated)}])
        io[role] = item
        item.start()

    def body_event(event, body, observation_id):
        # Handshakes and public GETs never stand in for an upload body.
        if not body.data: return
        findings = []
        complete = not body.limitations and not event.truncated
        if manifest.scenario == 'webhook' and len(body.data)>1024*1024:
            complete = False
        media = body.headers.get('content-type','').split(';',1)[0].strip().lower()
        supported = (manifest.scenario == 'webhook' and complete and media in {'text/plain','application/json'}
                     and body.headers.get('content-encoding','identity').strip().lower() in {'','identity'})
        if supported:
            try:
                text = body.data.decode('utf-8')
                if media == 'application/json': json.loads(text)
                findings = detect([ContentField(kind='unknown', location='$', value=text, bytes=len(body.data), sha256=digest(body.data))], index)
            except (UnicodeError, ValueError, RecursionError): supported = False
        with lock:
            tls_rows.append({'observation_id': observation_id, 'pid': event.pid, 'creation_filetime': event.creation_filetime,
                             'body_sha256': digest(body.data), 'body_bytes': len(body.data),
                             'complete': complete,
                             'findings': [f.model_dump() for f in findings], 'inspected': supported,
                             'limitations': list(body.limitations), 'capture_layer': 'tls', 'provider': 'ecapture'})

    def attach_tls(role):
        pipeline = Pipeline(output/('capture-' + role), ObservationPolicy(), body_sink=body_event)
        profile = Profile(image_sha256=subjects[role]['image_sha256'], application='business-' + manifest.scenario, mode='schannel')
        collector = ECaptureCollector(subjects[role], profile, paths['ecapture'], pipeline)
        captures[role] = (collector, pipeline)
        collector.start()

    def git_blob(body, metadata):
        findings = []; inspected = True
        try:
            text = body.decode('utf-8')
            if '\0' in text: raise ValueError('non_text_blob')
            findings = detect([ContentField(kind='unknown', location='$', value=text, bytes=len(body), sha256=digest(body))], index)
        except (UnicodeError, ValueError): inspected = False
        with lock:
            object_rows.append({**metadata, 'inspected': inspected, 'findings': [f.model_dump() for f in findings]})

    def before_git_reply(_):
        git_reply_ready.set()
        if not release_git_reply.wait(12): raise TimeoutError('capture_terminal_deadline')

    def close_capture(role):
        if role in finalized_captures:
            return
        capture, pipeline = captures[role]
        capture.close(); pipeline.finish()
        dump(output/('capture-'+role+'-health.json'), {'ready':capture.ready.is_set(),
            'terminal':bool(getattr(capture,'structured',None) and capture.structured.terminal),
            'errors':capture.errors,'native_initialization':capture.native_initialization,
            'lost_events':getattr(getattr(capture,'structured',None),'lost',0),'can_enforce':False})
        finalized_captures.add(role)

    try:
        state['controller'] = ScenarioProcess(role='controller', **{k: identity(os.getpid())[k]
                    for k in ('pid', 'creation_filetime', 'image_sha256')}).model_dump()
        capture_build = verify_build(paths['ecapture'])
        if capture_build.get('variant') != 'enhanced' or capture_build.get('protocol') != 'ECW2':
            raise ValueError('business_requires_enhanced_ecapture')
        if manifest.scenario == 'git':
            git_exec = Path(subprocess.check_output([str(paths['git']), '--exec-path'],timeout=5).decode().strip())
            git_helper_hashes = {name:digest((git_exec/name).read_bytes()) for name in
                                 ('git-remote-http.exe','git-remote-https.exe') if (git_exec/name).is_file()}
            if not git_helper_hashes: raise ValueError('git_helper_baseline_missing')
        dump(output/'baseline.json', {'executables': {k: v.sha256 for k, v in manifest.executables.items()},
             'build_inputs': {k: v.sha256 for k, v in manifest.build_inputs.items()}, 'worker_sha256': digest(worker.read_bytes()),
             'git_helper_sha256':git_helper_hashes,'git_tls_backend': manifest.git_tls_backend, 'can_enforce': False})
        task_config = control/'task.json'
        if manifest.scenario == 'webhook':
            script = powershell_task(task_config, control)
            command = '& '+ps_quote(paths['powershell'])+' -NoProfile -NonInteractive -EncodedCommand '+base64.b64encode(script.encode('utf-16-le')).decode()+'; exit $LASTEXITCODE'
        else:
            command = '& '+ps_quote(paths['python'])+' -I '+ps_quote(worker)+' --role transformer --control '+ps_quote(control)+' --config '+ps_quote(task_config)+'; exit $LASTEXITCODE'
        origin = BusinessOrigin(paths['certificate'], paths['private_key'], ticket_bytes=paths['source'].read_bytes(),
            git_root=work/'git-origin' if manifest.scenario == 'git' else None, git=paths.get('git'),
            on_git_blob=git_blob, reject_refs=manifest.case == 'reject_ref', git_auth_challenge=manifest.scenario == 'git',
            before_git_reply=before_git_reply, response_statuses=(503, 200) if manifest.case == 'retry' else (),
            model_reply=lambda body, row: model_events(command, workspace, body)).start()
        dump(task_config, {'incident': str(incident), 'generated': str(generated), 'case': manifest.case,
             'control_action':egress_action or 'observe',
             'url': origin.webhook_url if manifest.scenario == 'webhook' else origin.git_url,
             'git': str(paths.get('git', '')), 'git_tls_backend': manifest.git_tls_backend})
        export_config = control/'export.json'; dump(export_config, {'url': origin.ticket_url, 'incident': str(incident)})
        phase = 'exporter_ready'
        actors['exporter'] = subprocess.Popen([str(paths['python']), '-I', str(worker), '--role', 'exporter',
            '--control', str(control), '--config', str(export_config)], stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=0x08000000)
        ready = wait_file('exporter.ready.json')
        if ready['pid'] != actors['exporter'].pid: raise ValueError('exporter_identity_redirect')
        subject, process = enroll(ready['pid'], 'exporter', manifest.executables['python'].sha256)
        attach_io('exporter')
        exporter_etw = MultiApplicationETWCollector([{k: subject[k] for k in ('pid','creation_filetime','image_sha256')} | {'image_name': Path(subject['image_path']).name}],
             paths['etw'], output/'export-etw', run_id=session, duration=90, manifest=paths['native_manifest'])
        etws.append(exporter_etw)
        if exporter_etw.start()['state'] != 'ready': raise RuntimeError('export_etw_unavailable')
        state.update(state='observing', data_released=True); persist()
        (control/'exporter.release').touch()
        client_results['exporter'] = wait_file('exporter.done.json')
        io['exporter'].close(); exporter_etw.stop(); (control/'exporter.finish').touch()
        actors['exporter'].wait(timeout=5)

        phase = 'codex_ready'
        if manifest.scenario == 'webhook':
            # Do not let a fresh fixture inherit the enclosing source repo.
            # The application still uses its normal repository discovery.
            startup_git=Path(shutil.which('git.exe') or shutil.which('git') or '')
            if not startup_git.is_file(): raise RuntimeError('isolated_workspace_git_unavailable')
            subprocess.run([str(startup_git),'-c','core.hooksPath=NUL','init','--quiet','--initial-branch=fixture',str(workspace)],
                env=clean_environment(home),check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10)
            dump(output/'workspace-baseline.json',{'repository_scope':'fresh_fixture_only',
                'git_sha256':digest(startup_git.read_bytes()),'application_repository_discovery_disabled':False})
        (home/'config.toml').write_text('model_provider="business_probe"\napproval_policy="never"\nsandbox_mode="workspace-write"\n'
             '[sandbox_workspace_write]\nnetwork_access=true\n'
             '[features]\nplugins=false\napps=false\n[model_providers.business_probe]\nname="Business fixture"\n'
             f'base_url="{origin.url}"\nwire_api="responses"\nrequires_openai_auth=false\nrequest_max_retries=0\nstream_max_retries=0\nsupports_websockets=false\n'
             '[windows]\nsandbox="unelevated"\n', encoding='utf-8')
        actors['codex'] = subprocess.Popen([str(paths['codex']), 'exec', '--json', '--ephemeral', '--skip-git-repo-check',
             '--model', 'gpt-probe', '--cd', str(workspace), '-'], cwd=workspace, env=clean_environment(home),
             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, creationflags=0x08000000)
        # Drain client output immediately; persist only command result metadata.
        codex_outcomes = []
        def drain():
            stream = actors['codex'].stdout
            while True:
                line = stream.readline(1024*1024+1)
                if not line: break
                if len(line)>1024*1024:
                    while line and not line.endswith(b'\n'):
                        line=stream.readline(65536)
                    continue
                try: value=json.loads(line); item=value.get('item', {})
                except (ValueError,AttributeError): continue
                if item.get('type') == 'command_execution' and item.get('status') in {'completed','failed'}:
                    codex_outcomes.append({'status': item['status'], 'exit_code': item.get('exit_code')})
        drain_thread = threading.Thread(target=drain, daemon=True); drain_thread.start()
        subject, process = enroll(actors['codex'].pid, 'codex', manifest.executables['codex'].sha256)
        # An explicit fake-data observation policy; production policies untouched.
        policy = GuardPolicy(credential_rules=False)
        tap = GuardRequestTap(output/'codex-capture', subject, policy=policy)
        server = PipeServer(subject['pid'], PolicyEngine(policy), output/'codex-audit.jsonl', request_tap=tap)
        server.start(); injected = inject(subject['pid'], paths['guard_dll'], launched_cli=True)
        if not server.ready.wait(15): raise RuntimeError('codex_native_not_ready')
        native_ready = True
        behavior = CodexBehaviorCollector(injected, paths['behavior_etw'], output/'codex-etw', duration=manifest.timeout_seconds,
                                          file_profile='io-evidence' if egress_dll is not None else 'all')
        etws.append(behavior)
        if behavior.start()['state'] != 'ready': raise RuntimeError('codex_etw_unavailable')
        if egress_dll is not None:
            from transpect_trace.behavior.native_egress import EgressController
            egress=EgressController(injected,egress_dll,{'default_action':'allow','targets':[
                {'address':address,'port':origin.port,'action':egress_action,'protocol':'tcp'}
                for address in ('127.0.0.1','::1')]},output/'native-egress')
            egress.start()
            egress_ready_before_release=egress.state['state']=='active_limited' and egress.ready.is_set()
            if not egress_ready_before_release: raise RuntimeError('egress_not_ready_before_task')
        actors['codex'].stdin.write(b'Execute the supplied isolated fake-data business task. Report only completion.\n')
        actors['codex'].stdin.close()
        phase = 'transformer_ready'
        ready = wait_file('transformer.ready.json',timeout=120)
        expected = manifest.executables['powershell' if manifest.scenario == 'webhook' else 'python'].sha256
        subject, process = enroll(ready['pid'], 'transformer', expected)
        require_lineage(behavior, process)
        if egress is not None:
            with egress.lock:
                member=egress.members.get(subject['pid'])
                tool_enrolled_before_release=bool(member and member['creation_filetime']==subject['creation_filetime']
                    and member['registered'] and member['ready'] and not member['root']
                    and egress.state['state']=='active_limited' and not egress.errors)
            if not tool_enrolled_before_release: raise RuntimeError('tool_not_enrolled_before_release')
        attach_io('transformer')
        if manifest.scenario == 'webhook': attach_tls('transformer')
        (control/'transformer.release').touch()
        phase = 'business_upload'
        if manifest.scenario == 'git':
            handled = set()
            for number in range(2 if manifest.case == 'repeat' else 1):
                git_reply_ready.clear(); release_git_reply.clear()
                deadline = time.monotonic()+remaining(35)
                ready_files = []
                while time.monotonic()<deadline:
                    ready_files = [p for p in control.glob('git-helper-*.ready.json') if p not in handled]
                    if ready_files: break
                    if list(control.glob('*.error.json')): raise RuntimeError('git_worker_failed')
                    time.sleep(.025)
                if len(ready_files) != 1: raise RuntimeError('git_helper_rendezvous_unavailable')
                handled.add(ready_files[0])
                helper = json.loads(ready_files[0].read_text(encoding='utf-8'))['helper_pid']
                git_exec = subprocess.check_output([str(paths['git']), '--exec-path'], timeout=5).decode().strip()
                actual = identity(helper)
                expected_path = Path(git_exec)/Path(actual['image_path']).name
                if expected_path.name.lower() not in {'git-remote-http.exe','git-remote-https.exe'}:
                    raise ValueError('unexpected_git_transport')
                role = 'git-helper' if not number else f'git-helper-{number}'
                expected_hash = git_helper_hashes.get(expected_path.name.lower())
                if not expected_hash or digest(expected_path.read_bytes()) != expected_hash:
                    raise ValueError('git_helper_baseline_changed')
                subject, process = enroll(helper, role, expected_hash)
                require_lineage(behavior, process)
                attach_tls(role)
                (control/(ready_files[0].name.removesuffix('.ready.json')+'.release')).touch()
                deadline=time.monotonic()+remaining(35)
                while not git_reply_ready.wait(.05):
                    if (control/'transformer.done.json').exists(): break
                    if list(control.glob('*.error.json')) or time.monotonic()>deadline:
                        raise RuntimeError('git_receive_not_observed')
                close_capture(role); release_git_reply.set()
        client_results['transformer'] = wait_file('transformer.done.json')
        if manifest.scenario == 'webhook': close_capture('transformer')
        io['transformer'].close()
        (control/'transformer.finish').touch()
        actors['codex'].wait(timeout=remaining(25)); drain_thread.join(2)
        client_results['codex'] = {'exit_code': actors['codex'].returncode, 'tool_results': codex_outcomes}
        if egress is not None:
            # Freeze the protected observation window before an explicit
            # same-image, outside-tree negative control uses the receiver.
            with origin.lock: protected_receipts=list(origin.receipts)
            phase='same_image_scope_control'
            outside_body=b'{"report":"ordinary outside-tree scope control"}'
            outside_script="$null=[Console]::ReadLine(); $ErrorActionPreference='Stop'; [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; Invoke-RestMethod -Uri "+ps_quote(origin.webhook_url)+" -Method Post -ContentType 'application/json' -Body "+ps_quote(outside_body.decode())+" -TimeoutSec 15 | Out-Null"
            outside=subprocess.Popen([str(paths['powershell']),'-NoProfile','-NonInteractive','-EncodedCommand',
                base64.b64encode(outside_script.encode('utf-16-le')).decode()],stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,creationflags=0x08000000)
            actors['outside-scope-control']=outside
            other=identity(outside.pid)
            if other['image_sha256']!=manifest.executables['powershell'].sha256: raise ValueError('outside_image_changed')
            with egress.lock:
                outside_not_enrolled=outside.pid not in egress.members
                control_active=egress.state['state']=='active_limited' and not egress.stop.is_set()
            before=len(origin.receipts)
            outside.stdin.write(b'\n');outside.stdin.close();outside.wait(timeout=remaining(20))
            deadline=time.monotonic()+2
            while len(origin.receipts)==before and time.monotonic()<deadline: time.sleep(.01)
            after=origin.receipts[before:]
            unrelated_control={'pid':other['pid'],'creation_filetime':other['creation_filetime'],
                'image_sha256':other['image_sha256'],'not_enrolled':outside_not_enrolled,'controller_active':control_active,
                'exit_code':outside.returncode,'exact_body_received':any(r['route']=='webhook' and
                    r['body_sha256']==digest(outside_body) and r['body_bytes']==len(outside_body) and
                    r['completeness']=='complete' for r in after)}
        phase = 'terminal'
    except Exception as error:
        state['gaps'].append(phase+'_'+type(error).__name__)
        dump(output/'failure.json', {'phase': phase, 'error_type': type(error).__name__,
              'frames': [{'file':Path(f.filename).name,'line':f.lineno,'function':f.name} for f in traceback.extract_tb(error.__traceback__)]})
    finally:
        release_git_reply.set()
        for role in captures:
            try: close_capture(role)
            except Exception: state['gaps'].append('capture_finalize_failed')
        for collector in io.values():
            try: collector.close()
            except Exception: state['gaps'].append('io_finalize_failed')
        try:
            (control/'abort').touch()
            for name in ('exporter', 'transformer'): (control/(name+'.finish')).touch()
        except OSError: state['gaps'].append('owned_fixture_cancel_failed')
        for name, actor in actors.items():
            try:
                if actor.poll() is None:
                    try: actor.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        actor.terminate(); actor.wait(timeout=5); state['gaps'].append('owned_actor_cleanup_required')
            except (OSError, subprocess.TimeoutExpired): state['gaps'].append('owned_actor_cleanup_failed')
        if server:
            try: server.close()
            except Exception: state['gaps'].append('guard_finalize_failed')
        if tap:
            try: tap.close()
            except Exception: state['gaps'].append('request_capture_finalize_failed')
        for collector in etws:
            try:
                if hasattr(collector, 'stop'): collector.stop()
                else: collector.wait()
            except Exception: state['gaps'].append('etw_finalize_failed')
        if origin:
            try: origin.close()
            except Exception: state['gaps'].append('origin_finalize_failed')
        if egress:
            egress_state_before_close=egress.state['state']
            try: egress.close()
            except Exception: state['gaps'].append('egress_finalize_failed')

    # Build a report from independent evidence, never from fixture success alone.
    execution_gaps=list(state['gaps'])
    report.limitations.extend(state['gaps'])
    for role, subject in subjects.items():
        proc = process_for(role)
        stages = ['export'] if role == 'exporter' else ['transform'] if role == 'transformer' else ['tool'] if role == 'codex' else []
        for stage in stages:
            rows = [r for r in native_rows if r['pid'] == subject['pid'] and r['creation_filetime'] == subject['creation_filetime']
                    and r['kind'] in {'read','write'} and r['completed_length']]
            for row in rows:
                complete = (row.get('success') and not row.get('capture_gap') and not row.get('data_truncated') and
                            row['completed_length'] == row['data_bytes'])
                range_fields = (dict(file_identity=row['file_identity'], io_operation=row['kind'], io_offset=row['offset'])
                                if row.get('file_identity') and row.get('offset') is not None else {})
                if range_fields:
                    range_fields.update(io_started_qpc=row['qpc'],io_completed_qpc=row['completed_qpc'],qpc_frequency=row['qpc_frequency'])
                add(stage, 'native_io', proc, complete=complete, success=row.get('success'), event_ids=[row['evidence_id']],
                    body_sha256=row['data_sha256'], body_bytes=row['data_bytes'],
                    content_registration_ids=row['registration_ids'], **range_fields)
        for collector in etws:
            events = [e for e in collector.index.events if e.subject.pid == subject['pid']
                      and e.subject.creation_filetime == subject['creation_filetime'] and e.evidence_method.startswith('etw_')]
            for stage in stages:
                if events: add(stage, 'etw', proc, complete=True, event_ids=[e.event_id for e in events])
    for stage, role in [('export','exporter'),('transform','transformer'),('tool','codex')]:
        result = client_results.get(role)
        if result:
            success = (result.get('transform_success', result.get('success')) if role == 'transformer' else
                       result.get('success') if role != 'codex' else result.get('exit_code') == 0 and bool(result.get('tool_results')))
            add(stage, 'client_result', process_for(role), complete=True, success=bool(success))
    if tap:
        snapshot_file=output/'codex-capture/request-snapshots.jsonl'
        snapshots=[json.loads(line) for line in snapshot_file.read_text().splitlines()] if snapshot_file.exists() else []
        for row in snapshots:
            add('tool','native_request',process_for('codex'),complete=row['completeness']=='complete',
                body_sha256=row['payload_sha256'],body_bytes=row['payload_bytes'],event_ids=[row['observation_id']])
        status=tap.status()
        report.health['native_request']=CollectorHealth(ready=native_ready,terminal=status['terminal_health'],identity_verified=native_ready,
                    errors=len(status['errors']),lost_events=status['dropped_snapshots'],limitations=status['errors'])
    io_health=[c.status() for c in io.values()]
    report.health['native_io']=CollectorHealth(ready=bool(io_health) and all(h['ready'] for h in io_health),
         terminal=bool(io_health) and all(h['terminal'] for h in io_health),identity_verified=bool(io_health),
         errors=sum(len(h['errors']) for h in io_health),lost_events=sum(h['lost_events'] for h in io_health))
    etw_health=[c.index.health() for c in etws]
    report.health['etw']=CollectorHealth(ready=bool(etw_health) and all(h.get('ready_observed') for h in etw_health),
         terminal=bool(etw_health) and all(h.get('terminal_observed') for h in etw_health),identity_verified=bool(etw_health),
         errors=sum(len(h.get('gaps',[])) for h in etw_health),lost_events=sum(h.get('events_lost',0) for h in etw_health))
    # A process-start event alone cannot certify actual file/network behavior.
    for role, required in [('exporter', {'file.write'}), ('transformer', {'file.read', 'file.write'}),
                           ('transformer' if manifest.scenario=='webhook' else 'git-helper', {'network.activity'})]:
        subject = subjects.get(role)
        observed = {e.kind for c in etws for e in c.index.events if subject
                    and (e.subject.pid,e.subject.creation_filetime)==(subject['pid'],subject['creation_filetime'])
                    and e.evidence_method.startswith('etw_')}
        for missing in sorted(required-observed):
            gap = 'etw_'+role+'_'+missing.replace('.','_')+'_missing'
            report.limitations.append(gap)
            report.health['etw'].limitations.append(gap)
    report.health['ecapture']=CollectorHealth(ready=bool(captures) and all(c.ready.is_set() for c,p in captures.values()),
         terminal=bool(captures) and all(getattr(c,'structured',None) and c.structured.terminal for c,p in captures.values()),
         identity_verified=bool(captures),errors=sum(len(c.errors)+len(p.gaps) for c,p in captures.values()),
         lost_events=sum(getattr(getattr(c,'structured',None),'lost',0) for c,p in captures.values()))
    receipts=(protected_receipts if protected_receipts is not None else origin.receipts) if origin else []
    outbound_receipts=[r for r in receipts if r['route'] in {'webhook','git_receive'} and r['completeness']=='complete' and r['body_bytes']>0]
    stage='upload' if manifest.scenario=='webhook' else 'push'
    used=set()
    for row in tls_rows:
        matches=[(i,r) for i,r in enumerate(outbound_receipts) if i not in used and r['body_sha256']==row['body_sha256'] and r['body_bytes']==row['body_bytes']]
        # Ordered one-to-one accounting does not establish a unique causal mapping.
        attempt=matches[0][1]['attempt_id'] if matches else uuid4().hex
        proc=next(p for p in report.participants if p.key==(row['pid'],row['creation_filetime']))
        capture=add(stage,'ecapture',proc,attempt_id=attempt,body_sha256=row['body_sha256'],body_bytes=row['body_bytes'],
                    complete=row['complete'],event_ids=[row['observation_id']],
                    content_registration_ids=sorted({f['registration_id'] for f in row['findings'] if f.get('registration_id')}))
        receipt=None
        if matches:
            i,r=matches[0]; used.add(i)
            receipt=add(stage,'source_receipt',attempt_id=attempt,body_sha256=r['body_sha256'],body_bytes=r['body_bytes'],complete=True,success=True,event_ids=[r['receipt_id']])
        report.outbound.append(ScenarioOutbound(attempt_id=attempt,process=proc,capture_source='ecapture',capture_layer='tls',
            association_basis='ordered_body_multiset',
            completeness='complete' if row['complete'] else 'partial',body_sha256=row['body_sha256'],body_bytes=row['body_bytes'],
            capture_evidence_id=capture.evidence_id,receipt_evidence_id=receipt.evidence_id if receipt else None,
            detection_status=('matched' if row['findings'] else 'no_match') if row['inspected'] else ('unsupported' if manifest.scenario=='git' else 'incomplete'),
            findings=row['findings']))
    if len(used)!=len(outbound_receipts): report.limitations.append('unmatched_origin_attempts')
    for i, receipt in enumerate(outbound_receipts):
        if i not in used:
            add(stage, 'source_receipt', attempt_id=receipt['attempt_id'], complete=True, success=True,
                body_sha256=receipt['body_sha256'], body_bytes=receipt['body_bytes'],event_ids=[receipt['receipt_id']])
    if client_results.get('transformer'):
        add(stage,'client_result',process_for('transformer'),complete=True,success=client_results['transformer']['success'])
    if manifest.scenario=='git' and origin:
        integrate_git(report, origin.git_receipts, object_rows, add, client_results)
    link_content(report)
    for left,right in zip(report.stages,report.stages[1:]):
        left_e=next((e for e in report.evidence if e.stage_id==left.stage_id and e.provenance!='client_result'),None)
        right_e=next((e for e in report.evidence if e.stage_id==right.stage_id and e.provenance!='client_result'),None)
        if left_e and right_e:
            report.relations.append(ScenarioRelation(relation_id=uuid4().hex,left_id=left_e.evidence_id,right_id=right_e.evidence_id,
                confidence='Low',method='timing_candidate',evidence_ids=[left_e.evidence_id,right_e.evidence_id]))
    dump(output/'capture-summary.json',{'requests':tls_rows,'receipts':receipts,'git_receipts':origin.git_receipts if origin else [],
                'git_objects':object_rows,'io_health':io_health,'etw_health':etw_health,'client_results':client_results,'can_enforce':False})
    # Git object report integration is intentionally explicit below, not a scan
    # of the TLS pack bytes as ordinary text.
    report=assess(report)
    dump(output/'business-report.json',report.model_dump(mode='json'))
    state.update(state=report.state,certified=report.certified,gaps=report.limitations);persist()
    if egress_dll is not None:
        result=webhook_control_assessment(report,client_results,native_rows,tls_rows,receipts,
            egress_records=egress.records if egress else [],egress_errors=egress.errors if egress else ['not_started'],
            action=egress_action,port=origin.port if origin else 0,
            egress_ready=egress_ready_before_release,tool_ready=tool_enrolled_before_release,
            active_before_close=egress_state_before_close=='active_limited',
            origin_errors=origin.errors if origin else ['not_started'],runtime_gaps=execution_gaps,
            scope_control=unrelated_control)
        dump(output/'webhook-control.json',result)
    return state


def webhook_control_assessment(report, clients, io_rows, tls_rows, receipts, *, egress_records, egress_errors,
                               action, port, egress_ready, tool_ready, active_before_close, origin_errors, runtime_gaps,
                               scope_control=None):
    """A positive denial return and a clean receiver are both mandatory."""
    transformer=next((p for p in report.participants if p.role=='transformer'),None)
    exported=next((p for p in report.participants if p.role=='exporter'),None)
    observed=[row for row in io_rows if transformer and (row['pid'],row['creation_filetime'])==transformer.key
              and row.get('success') and not row.get('capture_gap') and row['data_bytes']==row['completed_length']]
    generated=[row for row in observed if row['kind']=='write' and row.get('path_role')=='transfer']
    reads=[row for row in observed if row['kind']=='read' and row.get('path_role')=='source']
    writes=[row for row in io_rows if exported and (row['pid'],row['creation_filetime'])==exported.key
            and row.get('success') and not row.get('capture_gap') and row['kind']=='write' and row.get('path_role')=='source']
    handoff=any(w.get('file_identity') and w.get('file_identity')==r.get('file_identity')
        and w.get('offset')==r.get('offset') and w['data_sha256']==r['data_sha256'] and w['data_bytes']==r['data_bytes']
        and w['qpc_frequency']==r['qpc_frequency'] and w['completed_qpc']<=r['qpc'] for w in writes for r in reads)
    target=[row for row in egress_records if transformer and row['kind']=='connection.decision'
            and (row['pid'],row['creation_filetime'])==transformer.key and row['destination_port']==port
            and row['destination_address'] in {'127.0.0.1','::1'}]
    key=lambda row:(row['run_id'],row['pid'],row['creation_filetime'],row['attempt_id'])
    rejections=[row for row in egress_records if row['kind']=='connection.rejected']
    rejected={key(row) for row in rejections if row['native_result']==-1 and row['winsock_error']==10013
              and row['evidence']=='native_failure_return_before_original_connect'}
    decisions={key(row) for row in target if row['decision']=='block'}
    source=[row for row in receipts if row['route']=='webhook']
    source_bytes=sum(row['body_bytes'] for row in source)
    tool=clients.get('transformer',{})
    codex=clients.get('codex',{})
    checks={
        'runtime_finished_without_cleanup_or_execution_failure':not runtime_gaps,
        'native_gate_ready_before_codex_task':bool(egress_ready),
        'tool_enrolled_and_ready_before_business_release':bool(tool_ready),
        'controller_active_through_task':bool(active_before_close) and not egress_errors,
        'independent_exporter_and_real_powershell':bool(transformer and exported and transformer.key!=exported.key),
        'observed_file_handoff':handoff,
        'sensitive_generated_text_observed':any(row.get('registration_ids') for row in generated),
        'tool_transformation_completed':tool.get('transform_success') is True,
        'official_codex_completed':codex.get('exit_code')==0 and bool(codex.get('tool_results')),
        'native_io_health':bool(report.health.get('native_io') and report.health['native_io'].complete),
        'etw_terminal_without_loss':bool(report.health.get('etw') and report.health['etw'].ready and
             report.health['etw'].terminal and report.health['etw'].identity_verified and
             not report.health['etw'].lost_events and not report.health['etw'].errors and
             not set(report.health['etw'].limitations)-({'etw_transformer_network_activity_missing'} if action=='block' else set())),
        'ecapture_health':bool(report.health.get('ecapture') and report.health['ecapture'].complete),
        'guard_request_capture_health':bool(report.health.get('native_request') and report.health['native_request'].complete),
        'source_healthy_without_inflight_failure':not origin_errors,
        'same_image_outside_tree_works':bool(scope_control and scope_control.get('not_enrolled') is True and
            scope_control.get('controller_active') is True and scope_control.get('exit_code')==0 and
            scope_control.get('exact_body_received') is True),
    }
    if action=='block':
        checks.update(native_block_return_paired=bool(decisions) and decisions<=rejected,
            every_target_decision_blocked=bool(target) and all(row['decision']=='block' for row in target),
            source_webhook_body_zero=source_bytes==0 and not source,
            real_upload_failed=tool.get('success') is False and bool(tool.get('attempts')) and
                all(row.get('success') is False for row in tool.get('attempts',[])))
    else:
        capture=[row for row in tls_rows if row['complete'] and row['inspected']]
        from collections import Counter
        pairs=lambda rows:Counter((row['body_sha256'],row['body_bytes']) for row in rows)
        checks.update(native_target_allowed=bool(target) and all(row['decision']=='allow' for row in target),
            exact_upload_received=bool(source) and all(row['completeness']=='complete' for row in source) and
                any(g['data_sha256']==r['body_sha256'] and g['data_bytes']==r['body_bytes'] for g in generated for r in source),
            ecapture_source_hash_length_count_match=bool(capture) and len(capture)==len(tls_rows) and pairs(capture)==pairs(source),
            sensitive_body_detected=bool(capture) and all(row['findings'] for row in capture),
            real_upload_completed=tool.get('success') is True)
    return {'schema_version':'transpect.webhook-control/1.0','action':action,'passed':all(checks.values()),
        'checks':checks,'source_body_bytes':source_bytes,'source_attempts':len(source),'native_target_decisions':target,
        'native_rejections':rejections,'tool_result':tool,'origin_errors':list(origin_errors),
        'execution_gaps':list(runtime_gaps),'scope':'explicit_codex_descendants_tcp_target','can_enforce':False,
        'same_image_outside_tree_control':scope_control,
        'protection_active_now':False,'content_based_blocking':False,'connection_policy_basis':'explicit_test_target',
        'business_transport':'regular_file_and_https_not_experimental_business_pipe',
        'limitations':['new_connections_only','loader_tls_callback_window_not_certified','UDP_QUIC_existing_connections_not_covered',
                       'source_content_relation_candidate_not_unique_source']}


def integrate_git(report, receipts, objects, add, client_results):
    """Receiver object inspection remains distinct from transport capture."""
    from .models import ScenarioObjectDetection, ScenarioGitObjectScan
    for receipt in receipts:
        attempt=receipt['attempt_id']
        matches=[row for row in objects if row['attempt_id']==attempt]
        count=sum(r['object_type']=='blob' for r in receipt.get('new_objects',[]))
        scan=add('push','git_object',attempt_id=attempt,
                 complete=bool(receipt.get('inspection_complete') and receipt.get('quarantine_observed') and not receipt.get('limitations')),
                 object_location='origin',observed_blob_count=count)
        report.git_scans.append(ScenarioGitObjectScan(attempt_id=attempt,evidence_id=scan.evidence_id,
                                received_blob_count=count,complete=scan.complete))
        for row in matches:
            evidence=add('commit','git_object',attempt_id=attempt,complete=row['inspected'],object_id=row['object_id'],
                 object_location='origin',body_sha256=row['content_sha256'],body_bytes=row['object_bytes'],
                 content_registration_ids=sorted({f['registration_id'] for f in row['findings'] if f.get('registration_id')}))
            report.git_objects.append(ScenarioObjectDetection(attempt_id=attempt,object_id=row['object_id'],
                 body_sha256=row['content_sha256'],body_bytes=row['object_bytes'],evidence_id=evidence.evidence_id,
                 detection_status=('matched' if row['findings'] else 'no_match') if row['inspected'] else 'incomplete',findings=row['findings']))
    if receipts and client_results.get('transformer'):
        add('commit','client_result',complete=True,success=client_results['transformer'].get('commit_success',False))


def link_content(report):
    """Construct bounded content candidates, never a unique-source assertion."""
    inputs = [e for e in report.evidence if e.provenance == 'native_io' and e.complete and e.body_bytes]
    if len(inputs)>2048:
        report.limitations.append('content_relation_limit'); return
    for left in inputs:
        for right in report.evidence:
            if right is left or not right.complete or not right.body_bytes:
                continue
            exact = left.body_sha256 == right.body_sha256 and left.body_bytes == right.body_bytes
            registered = bool(set(left.content_registration_ids) & set(right.content_registration_ids))
            if not (exact or registered):
                continue
            handoff = (right.provenance == 'native_io' and left.file_identity and left.file_identity == right.file_identity
                       and left.io_operation == 'write' and right.io_operation == 'read'
                       and left.io_offset == right.io_offset and left.process and right.process
                       and left.process.key != right.process.key and exact)
            downstream = (left.stage_id == 'transform' and (right.provenance in {'ecapture','git_object'} or
                          right.stage_id == 'transform' and right.provenance == 'native_io'))
            if handoff or downstream:
                report.relations.append(ScenarioRelation(relation_id=uuid4().hex,left_id=left.evidence_id,right_id=right.evidence_id,
                    confidence='Medium',method='observed_file_handoff' if handoff else 'content_candidate',
                    evidence_ids=[left.evidence_id,right.evidence_id]))
