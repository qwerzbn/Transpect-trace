"""Isolated fake-data Schannel baseline; no general-client certification."""
import argparse,json,subprocess,time,queue,threading,os
from collections import Counter
from pathlib import Path
from uuid import uuid4
from probe_codex_tls import certificate,Origin
from transpect_trace.observe.ecapture import ECaptureCollector,PIN,verify_build
from transpect_trace.observe.elevation import is_elevated
from transpect_trace.observe.windows import discover_profile,modules,digest
from transpect_trace.observe.pipeline import Pipeline
from transpect_trace.guard.policy import GuardPolicy


def experiment(root,executable,*,elevate=False,semantic_payload=None,semantic_sink=None):
    root.mkdir(parents=True,exist_ok=False);manifest=verify_build(executable)
    cert,key,ca=certificate(root)
    body=root/'fake.json';body.write_text(json.dumps(semantic_payload if semantic_payload is not None else
        {'model':'fixture','input':'FAKE_ECAPTURE_PROBE 中文 '*300},ensure_ascii=False),encoding='utf-8')
    enhanced=manifest.get('variant')=='enhanced'
    fixture=executable.parent/'ecapture_fixture.exe' if enhanced else Path('build/observe/schannel_fixture.exe').resolve()
    if enhanced and digest(fixture)!=manifest['artifacts_sha256'].get('ecapture_fixture.exe'):raise ValueError('fixture_build_mismatch')
    origin=Origin(root,cert,key,b'FAKE_ECAPTURE_PROBE');origin.thread.start()
    child=subprocess.Popen([str(fixture),str(origin.port),str(body),*(['2','2'] if enhanced else [])],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
    pipeline=Pipeline(root,GuardPolicy(),semantic_sink=semantic_sink);collector=None;available=False;reason=None;subject=None;libraries=[];target_elevated=None
    try:
        if child.stdout.readline().strip()!=b'ready':raise RuntimeError('fixture unavailable')
        subject,profile=discover_profile(child.pid,'schannel-fixture','schannel')
        target_elevated=is_elevated(child.pid)
        collector=ECaptureCollector(subject,profile,executable,pipeline,elevate=elevate)
        try:
            collector.start();available=True;child.stdin.write(b'1');child.stdin.flush()
            messages=queue.Queue()
            threading.Thread(target=lambda:messages.put(child.stdout.readline()),daemon=True).start()
            if messages.get(timeout=20).strip()!=b'sent':raise RuntimeError('fixture send failed')
            time.sleep(.3)
        except (OSError,RuntimeError,queue.Empty):reason='collector_or_fixture_failed'
    finally:
        if collector:collector.close()
        if child.poll() is None:
            libraries=[{'path':m['path'],'sha256':digest(Path(m['path']))} for m in modules(child.pid)
                       if Path(m['path']).name.lower() in {'secur32.dll','sspicli.dll','schannel.dll','winhttp.dll'}]
        if child.poll() is None:child.terminate();child.wait(timeout=5)
        if child.stdin:child.stdin.close()
        if child.stdout:child.stdout.close()
        origin.stop.set();origin.thread.join(timeout=10);origin.listener.close()
    pipeline.finish()
    receipts=[{'payload_sha256':r['payload_sha256'],'payload_bytes':r.get('payload_bytes')} for r in origin.records if r.get('payload_sha256')]
    (root/'origin-receipts.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in receipts),encoding='utf-8')
    terminal=bool(collector and hasattr(collector,'structured') and collector.structured.terminal)
    errors=list(collector.errors) if collector else ['collector_not_started']
    expected=Counter(r['payload_sha256'] for r in receipts)
    actual=Counter(r['content_sha256'] for r in pipeline.rows if r['completeness']=='complete')
    passed=bool(expected and expected==actual and terminal and not errors and not pipeline.gaps)
    if subject:subject={**subject,'parent_pid':os.getpid(),'lineage_evidence':'controller_created_child'}
    result={**PIN,**{k:manifest[k] for k in ('transport','connection_identity','text_preview_limit')},
            'collector_variant':manifest.get('variant','upstream'),'scope':'controlled_origin',
            'process':subject,'tls_backend':'Schannel','tls_modules':libraries,'protocol':'http/1.1','destination':'https://localhost',
            'payload_size':body.stat().st_size,'runtime_available':available,'reason':reason,'collector_errors':errors,
            'collector_elevation':collector.elevation_state if collector else 'not_started',
            'etw_session_started':collector.etw_started if collector else False,
            'controller_elevated':is_elevated(),'target_elevated':target_elevated,
            'capture_status':'supported' if passed else 'partial' if pipeline.rows else 'unavailable' if not available else 'not_verified',
            'terminal_health_confirmed':terminal,'origin_request_count':len(receipts),'complete_request_observations':len(pipeline.rows),
            'plaintext_validation_passed':passed,'metadata_validation_passed':False,'can_enforce':False,
            'actual_ai_channel_certified':False,'limitations':[] if passed else ['Runtime requires elevation; full capture requires ECW2 and terminal health.'],
            'fixture_cleanup_terminated_child':True}
    (root/'summary.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,default=Path('runs/ecapture/baseline')/uuid4().hex)
    parser.add_argument('--variant',choices=['upstream','enhanced'],default='upstream')
    parser.add_argument('--elevate',action='store_true',help='Request Windows UAC for the enhanced collector only.')
    args=parser.parse_args()
    exe=Path('build/observe/ecapture-enhanced/ecapture.exe' if args.variant=='enhanced' else 'build/observe/ecapture.exe')
    if args.elevate:print('Windows UAC may request confirmation for eCapture.',flush=True)
    result=experiment(args.output.resolve(),exe,elevate=args.elevate)
    print(json.dumps(result,indent=2))
    if not result['plaintext_validation_passed']:raise SystemExit(1)


if __name__=='__main__':main()
