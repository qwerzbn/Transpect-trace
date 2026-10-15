"""Record eCapture's actual privilege/preview boundary using a fake origin."""
import argparse,json,subprocess,time
from pathlib import Path
from uuid import uuid4
from probe_codex_tls import certificate,Origin
from transpect_trace.observe.ecapture import ECaptureCollector,PIN
from transpect_trace.observe.windows import discover_profile
from transpect_trace.observe.pipeline import Pipeline
from transpect_trace.guard.policy import GuardPolicy


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,default=Path('runs/ecapture-probes')/uuid4().hex);args=parser.parse_args()
    root=args.output.resolve();root.mkdir(parents=True,exist_ok=False);cert,key,ca=certificate(root)
    body=root/'fake.json';body.write_text('{"model":"fixture","input":"FAKE_ECAPTURE_PROBE"}')
    origin=Origin(root,cert,key,b'FAKE_ECAPTURE_PROBE');origin.thread.start()
    child=subprocess.Popen([str(Path('build/observe/schannel_fixture.exe').resolve()),str(origin.port),str(body)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
    collector=None;available=False;reason=None
    try:
        if child.stdout.readline().strip()!=b'ready':raise RuntimeError('fixture unavailable')
        subject,profile=discover_profile(child.pid,'schannel-fixture','schannel');pipeline=Pipeline(root,GuardPolicy())
        collector=ECaptureCollector(subject,profile,Path('build/observe/ecapture.exe'),pipeline)
        try:
            collector.start();available=True;child.stdin.write(b'1');child.stdin.flush();child.stdout.readline();time.sleep(1)
        except RuntimeError:reason='collector_start_failed'
    finally:
        if collector:collector.close()
        if child.poll() is None:child.terminate();child.wait(timeout=5)
        origin.stop.set();origin.thread.join(timeout=10);origin.listener.close()
    pipeline.finish()
    result={**PIN,'runtime_available':available,'reason':reason,'errors':collector.errors,
            'origin_request_count':len(origin.records),'complete_request_observations':len(pipeline.rows),
            'plaintext_validation_passed':False,'metadata_validation_passed':False,'can_enforce':False,
            'known_limitations':['ETW elevation required','upstream preview limited to 120 bytes','no TLS connection ID'],
            'fixture_cleanup_terminated_child':True}
    (root/'summary.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))


if __name__=='__main__':main()
