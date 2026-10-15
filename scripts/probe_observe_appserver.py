"""Observe the isolated VS Code Codex extension's bundled backend.

Does not certify the extension UI, authentication flows or all app-server paths.
"""
import argparse,hashlib,json,os,queue,subprocess,threading,time
from pathlib import Path
from uuid import uuid4
from probe_codex_tls import certificate,Origin
from transpect_trace.observe.windows import discover_profile
from transpect_trace.observe.native import NativeCollector
from transpect_trace.observe.pipeline import Pipeline,report
from transpect_trace.guard.policy import GuardPolicy,Marker


def experiment(root,binary,transport):
    root.mkdir(parents=True,exist_ok=False);home=root/'home';home.mkdir();workspace=root/'workspace';workspace.mkdir()
    marker='TRANSPECT_IDE_BACKEND_'+uuid4().hex;cert,key,ca=certificate(root)
    origin=Origin(root,cert,key,marker.encode());origin.thread.start()
    (home/'config.toml').write_text('model_provider = "fixture"\n[features]\nplugins = false\napps = false\n'
      '[model_providers.fixture]\nname = "Local fixture"\n'+f'base_url = "https://localhost:{origin.port}"\nwire_api = "responses"\n'
      'requires_openai_auth = false\nrequest_max_retries = 0\nstream_max_retries = 0\n'+f'supports_websockets = {str(transport=="wss").lower()}\n')
    env={k:v for k,v in os.environ.items() if 'PROXY' not in k.upper() and not k.upper().endswith('API_KEY') and k.upper() not in {'CODEX_HOME','CODEX_CA_CERTIFICATE','SSL_CERT_FILE','SSLKEYLOGFILE','OPENAI_BASE_URL'}}
    env.update(CODEX_HOME=str(home),CODEX_CA_CERTIFICATE=str(ca),HTTP_PROXY='',HTTPS_PROXY='',ALL_PROXY='',NO_PROXY='*')
    with (root/'synthetic-backend.stderr.log').open('wb') as log:
        process=subprocess.Popen([str(binary),'app-server'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=log,env=env,cwd=workspace)
        mailbox=queue.Queue()
        def read():
            for line in process.stdout:
                try:mailbox.put(json.loads(line))
                except ValueError:pass
        threading.Thread(target=read,daemon=True).start()
        def send(method,params=None,id=None):
            row={'method':method}
            if params is not None:row['params']=params
            if id is not None:row['id']=id
            process.stdin.write(json.dumps(row).encode()+b'\n');process.stdin.flush()
        def response(id):
            deadline=time.monotonic()+20
            while time.monotonic()<deadline:
                row=mailbox.get(timeout=max(0.1,deadline-time.monotonic()))
                if row.get('id')==id:
                    if 'error' in row:raise RuntimeError('isolated backend RPC failed')
                    return row['result']
            raise TimeoutError('backend RPC timeout')
        collector=None;pipeline=Pipeline(root,GuardPolicy(content_markers=[Marker(marker_id='fake-source',value=marker,source_path='fixture')]))
        try:
            send('initialize',{'clientInfo':{'name':'transpect-observe-fixture','version':'1'},'capabilities':{'experimentalApi':True}},1);response(1);send('initialized')
            subject,profile=discover_profile(process.pid,'vscode-codex');collector=NativeCollector(subject,profile,Path('build/observe/ttrace-observe.dll'),pipeline);collector.start()
            send('thread/start',{'model':'gpt-probe','modelProvider':'fixture','cwd':str(workspace),'approvalPolicy':'never','sandbox':'read-only','ephemeral':True},2)
            thread=response(2)['thread']['id']
            send('turn/start',{'threadId':thread,'input':[{'type':'text','text':'Do not run tools. Reply OK. Fake marker: '+marker}]},3);response(3)
            deadline=time.monotonic()+25
            while time.monotonic()<deadline:
                row=mailbox.get(timeout=max(0.1,deadline-time.monotonic()))
                if row.get('method')=='turn/completed':break
            deadline=time.monotonic()+5
            while time.monotonic()<deadline and not any(r['risk']=='critical' for r in pipeline.assessments):time.sleep(0.05)
        finally:
            if collector:collector.close()
            process.stdin.close()
            try:process.wait(timeout=8)
            except subprocess.TimeoutExpired:process.terminate();process.wait(timeout=5)
            origin.stop.set();origin.thread.join(timeout=10);origin.listener.close()
    pipeline.finish();origin_hashes={row.get('payload_sha256') for row in origin.records}
    matches=[row for row in pipeline.rows if row['content_sha256'] in origin_hashes and row['completeness']=='complete']
    result={'client':'vscode-codex-bundled-backend','transport':transport,'identity':subject,'profile':profile.model_dump(),
            'observer_dll_sha256':hashlib.sha256(Path('build/observe/ttrace-observe.dll').read_bytes()).hexdigest(),
            'complete_hash_matches':len(matches),'sensitive_matches':sum(r['risk']=='critical' for r in pipeline.assessments),
            'collector_errors':collector.errors,
            'origin_connections':origin.records,'can_enforce':False,'actual_ai_channel_certified':False,
            'scope':'isolated app-server backend only; VS Code UI not certified',
            'passed':bool(matches) and any(r.get('marker_in_origin_payload') for r in origin.records) and not pipeline.gaps and not collector.errors}
    (root/'status.json').write_text(json.dumps({'state':'stopped','can_enforce':False}))
    (root/'summary.json').write_text(json.dumps(result,indent=2)+'\n');(root/'report.json').write_text(json.dumps(report(root),indent=2)+'\n')
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--codex',type=Path);parser.add_argument('--transport',choices=['http','wss'],default='http')
    parser.add_argument('--output',type=Path,default=Path('runs/observe-backend')/uuid4().hex);args=parser.parse_args()
    binary=args.codex or next(Path('.external/observe-vscode-extensions').rglob('codex.exe'))
    result=experiment(args.output.resolve(),binary.resolve(),args.transport)
    print(json.dumps({k:v for k,v in result.items() if k not in {'profile','origin_connections'}},indent=2))
    if not result['passed']:raise SystemExit(1)


if __name__=='__main__':main()
